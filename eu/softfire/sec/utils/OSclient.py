import eu.softfire.sec.utils.utils as utils
from eu.softfire.sec.exceptions.exceptions import OpenStackDeploymentError
import json

from keystoneauth1 import identity
from keystoneauth1 import session
from keystoneauth1 import loading
from novaclient import client as nova_client
from glanceclient import client as glance_client
from neutronclient.v2_0 import client as neutron_client

import hashlib
import time

logger = utils.get_logger(utils.config_path, __name__)

class OSclient :

    def __init__(self, testbed, exp_username, exp_tenant_id):
        os_credentials_file = utils.get_config("openstack", "credentials-file", utils.config_path)
        with open(os_credentials_file) as credentials_file:
            credentials = json.load(credentials_file)
        testbed_info = credentials[testbed]

        self.testbed_name = testbed
        self.tenant_name = exp_username
        self.project_id = exp_tenant_id
        self.project_domain_name = testbed_info["project_domain_name"] or "Default"
        self.user_domain_id = testbed_info['user_domain_id'] or 'Default'
        self.api_version = testbed_info["api_version"]
        self.username = testbed_info["username"]
        self.password = testbed_info["password"]
        self.auth_url = testbed_info["auth_url"]
        if self.auth_url.endswith('/'):
            self.auth_url = self.auth_url[:-1]
        self.admin_tenant_name = testbed_info["admin_tenant_name"]
        self.admin_project_id = testbed_info["admin_project_id"]


        #self.ext_net = testbed_info["ext_net_name"]
        #self.domain_name = testbed_info["user_domain_name"]
        #self.exp_username = exp_username
        #self.exp_tenant_id = exp_tenant_id

        #self.logger = utils.get_logger(utils.config_path, __name__)

        #if self.api_version == 2:
        #    OSloader = loading.get_plugin_loader('password')
        #    auth = OSloader.load_from_options(
        #        auth_url=self.auth_url,
        #        username=self.admin_username,
        #        password=self.password,
        #        tenant_name=exp_tenant_id,
        #    )

        if self.api_version == 3:
            auth = identity.v3.Password(
                auth_url = self.auth_url,
                #username=self.admin_username,
                username = self.username,
                password = self.password,
                project_id = self.project_id,
                project_domain_name = self.project_domain_name,
                #project_domain_name=self.domain_name,
                #user_domain_name=self.domain_name,
                user_domain_id = self.user_domain_id
                #project_id=exp_tenant_id
            )

        self.os_session = session.Session(auth=auth)

        self.nova = nova_client.Client("2.1", session=self.os_session)
        self.neutron = neutron_client.Client(session=self.os_session)
        self.glance = glance_client.Client("2", session=self.os_session)

    def get_fl_ip_from_id(self, instance_id):
        s = self.nova.servers.get(instance_id)
        for v in s.addresses.values():
            for a in v:
                if a["OS-EXT-IPS:type"] == "floating":
                    return a["addr"]

    def deploy_pfSense(self, selected_networks: dict):
        image_name = utils.get_config("pfsense", "image_name", utils.config_path)
        flavor = utils.get_config("pfsense", "flavor_name", utils.config_path)
        extended_name = "pfsense-" + utils.random_string(6)

        networks = self.neutron.list_networks(tenant_id=self.project_id)["networks"]
        network_names = [x["name"] for x in networks]
        net_names = [selected_networks["wan"], selected_networks["lan"]]

        #TODO cambiare tutte le print, mettere log e togliere riferimenti a Zabbix

        logger.debug("# network requested: %d" % len(net_names))
        for network in net_names:
            if network in network_names:
                logger.debug("network found {}".format(network))
            else:
                try:
                    logger.debug("network not found, trying to create it")

                    kwargs = {'network': {
                        'name': network,
                        'shared': False,
                        'admin_state_up': True
                    }}
                    logger.debug("Creating net {}".format(network))

                    network_ = self.neutron.create_network(body=kwargs)['network']

                    logger.debug("net created {}".format(network_))
                    s = self.tenant_name + network
                    rand_num = int(hashlib.sha1(s.encode('utf-8')).hexdigest(), base=16) % 254 + 1
                    kwargs = {
                        'subnets': [
                            {
                                'name': "subnet_%s" % network,
                                'cidr': "192.%s.%s.0/24" % (rand_num, 1),
                                'gateway_ip': '192.%s.%s.1' % (rand_num, 1),
                                'ip_version': '4',
                                'enable_dhcp': True,
                                'dns_nameservers': ['8.8.8.8'],
                                'network_id': network_['id']
                            }
                        ]
                    }
                    subnet = self.neutron.create_subnet(body=kwargs)
                    logger.debug("Created subnet {}".format(subnet))

                    #Get first router. If no router exists -> ERROR
                    router = self.neutron.list_routers(tenant_id=self.project_id)["routers"][0]
                    router_id = router['id']
                    body_value = {
                        'subnet_id': subnet["subnets"][0]['id'],
                    }

                    self.neutron.add_interface_router(router=router_id, body=body_value)

                    logger.debug("network successfully created and configured")
                except Exception as e:
                    print(e)

        new_server = self.nova.servers.create(
            name=extended_name,
            image=self.nova.glance.find_image(image_name),
            flavor=self.nova.flavors.find(name=flavor),
            nics=[{'net-id': self.neutron.list_networks(tenant_id=self.project_id, name=n)["networks"][0]["id"]} for n in
                  net_names]
        )
        id = new_server.id
        logger.debug("pfSense created, id is {}".format(id))

        openstack_build_timeout = float(240.0)  # seconds
        wait_quantum = 0.3  # seconds
        current_attempt = 0
        max_attempts = openstack_build_timeout / wait_quantum

        while True:
            new_server = self.nova.servers.get(id)
            status = new_server.status

            #logger.debug("zabbix attempt {} server status: {}".format(current_attempt, status))
            if status != "BUILD":
                break
            time.sleep(wait_quantum)
            current_attempt += 1

            if current_attempt > max_attempts:
                raise OpenStackDeploymentError(message="Timeout in openstack server building process")

        logger.debug("pfSense instance is ACTIVE")
        floating_ip_to_add = None
        flips = self.neutron.list_floatingips()
        for ip in flips["floatingips"]:
            if hasattr(ip, "project_id") and ip['project_id']:
                ip_project_id_ = ip['project_id']
            else:
                ip_project_id_ = ip['tenant_id']
            if ip["fixed_ip_address"] is None and ip_project_id_ == self.project_id:
                floating_ip_to_add = ip["floating_ip_address"]
                break

        if floating_ip_to_add:
            new_server.add_floating_ip(floating_ip_to_add)
            logger.debug("floating ip {0} added".format(floating_ip_to_add))
        else:
            OpenStackDeploymentError(message="Unable to associate Floating IP")

        return {"id" : id, "ip" : floating_ip_to_add}

    def delete_server(self, server_id):
        logger.debug("Deleting server {0}".format(server_id))
        s = self.nova.servers.get(server_id)
        s.delete()

    def allow_forwarding(self, server_id):
        logger.debug("")
        try:
            interface_list = self.neutron.list_ports(device_id=server_id)["ports"]
        except Exception as e:
            print(e)
        print(interface_list)
        global ret
        for i in interface_list:
            # ret = neutron.update_port(i["id"], {"port":{"port_security_enabled": False, "security_groups" : []}})
            ret = self.neutron.update_port(i["id"], {"port": {"allowed_address_pairs": [{"ip_address": "0.0.0.0/0", "mac_address": i["mac_address"]}]}})
            logger.debug(ret)
            print(ret)

    def upload_image(self, image_name, path):
        i = self.glance.images.create(name=image_name, disk_format="qcow2", container_format="bare", visibility="public", protected=True)
        self.glance.images.upload(i.id, open(path, 'rb'))

if __name__ == "__main__" :
    import sys
    import os

    """Useful to upload the image to a testbed"""
    os.environ["http_proxy"] = ""
    argv = sys.argv

    print(argv)
    if argv[1] == "upload":
        print("upload")
        testbed = argv[2]
        tenant_id = argv[3]
        img_name = argv[4]
        path = argv[5]

        openstack = OSclient(testbed, "", tenant_id)
        openstack.upload_image(img_name, path)


