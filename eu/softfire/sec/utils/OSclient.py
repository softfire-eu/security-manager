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
import logging

logger = utils.get_logger(utils.config_path, __name__)
logging.getLogger("novaclient.v2.client").setLevel(logging.WARNING)

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

        if self.api_version == 3:
            auth = identity.v3.Password(
                auth_url = self.auth_url,
                username = self.username,
                password = self.password,
                project_id = self.project_id,
                project_domain_name = self.project_domain_name,
                user_domain_id = self.user_domain_id
            )
        else:
            logger.error("API version < 3")
	
        logger.info("Opening OS session for project:%s" % self.project_id)
       	logger.debug("auth url: %s" % self.auth_url)
       	logger.debug("username: %s" % self.username)
       	logger.debug("password: %s" % self.password)
       	logger.debug("project id: %s" % self.project_id)
       	logger.debug("project domain name: %s" % self.project_domain_name)
       	logger.debug("user domain name: %s" % self.user_domain_id)
        self.os_session = session.Session(auth=auth)

        logger.debug("nova client init")
        self.nova = nova_client.Client("2.1", session=self.os_session)

        logger.debug("neutron client init")
        self.neutron = neutron_client.Client(session=self.os_session)

        logger.debug("glance client init")
        self.glance = glance_client.Client("2", session=self.os_session)

    def get_fl_ip_from_id(self, instance_id):
        s = self.nova.servers.get(instance_id)
        for v in s.addresses.values():
            for a in v:
                if a["OS-EXT-IPS:type"] == "floating":
                    return a["addr"]

    def list_networks(self):
        networks_list = self.neutron.list_networks()['networks']
        logger.debug("found %d networks" % len(networks_list))
        for n in networks_list:
            logger.debug("net_name: %s, shared: %s, project_id: %s" % (n['name'], n['shared'], n['project_id']))
        return {n['name']: n for n in networks_list}

    def deploy_pfSense(self, selected_networks: dict):
        ext_net = None
        logger.info("Deploing pfsense")
        image_name = utils.get_config("pfsense", "image_name", utils.config_path)
        flavor = utils.get_config("pfsense", "flavor_name", utils.config_path)
        extended_name = "pfsense-" + utils.random_string(6)
        logger.debug("image name: %s, flavor: %s, resource_id: %s" % (image_name, flavor, extended_name))

        logger.info("Listing networks")
        networks = self.list_networks()


        logger.info("checking networks")
        for k in selected_networks.keys():
            if selected_networks[k] in networks.keys() and (networks[selected_networks[k]]['shared'] or networks[selected_networks[k]]['project_id'] == self.project_id):
                logger.info("'%s' network found" % selected_networks[k])
            else:
                logger.info("'%s' network not found. Creating..." % selected_networks[k])
                try:
                    #Network configs
                    kwargs = {'network': {
                        'name': selected_networks[k],
                        'shared': False,
                        'admin_state_up': True
                    }}
                    logger.debug("New network: {}".format(selected_networks[k]))

                    network_result = self.neutron.create_network(body=kwargs)['network']
                    networks[selected_networks[k]] = network_result
                    logger.debug("network result {}".format(network_result))

                    #subnet configs
                    s = self.tenant_name + selected_networks[k]
                    rand_num = int(hashlib.sha1(s.encode('utf-8')).hexdigest(), base=16) % 254 + 1
                    kwargs = {
                        'subnets': [
                            {
                                'name': "subnet_%s" % selected_networks[k],
                                'cidr': "192.%s.%s.0/24" % (rand_num, 1),
                                'gateway_ip': '192.%s.%s.1' % (rand_num, 1),
                                'ip_version': '4',
                                'enable_dhcp': True,
                                'dns_nameservers': ['8.8.8.8'],
                                'network_id': network_result['id']
                            }
                        ]
                    }
                    subnet_result = self.neutron.create_subnet(body=kwargs)
                    logger.debug("subnet result {}".format(subnet_result))

                    if k == 'wan' or True:
                        logger.info("Connecting WAN to a gateway router")
                        logger.debug("lokking inside id: %s" % self.project_id)
                        routers =  [r for r in self.neutron.list_routers()["routers"] if r["tenant_id"] == self.project_id]
                        logger.debug(routers)
                        if len(routers) > 0:
                            router_id = routers[0]['id']
                            logger.debug("router found. id = %s" % router_id)
                        else:
                            logger.debug("router not found creating")
                            router_request = {'router': {'tenant_id': self.project_id,
                                                         'project_id': self.project_id,
                                                         'admin_state_up': True,
                                                         'distributed': False,
                                                         'name': "{}_gateway".format(self.tenant_name),}}
                            router_result = self.neutron.create_router(router_request)
                            logger.debug(router_result)
                            
                            #softfire-network network_id (external)
                            ext_net = [ext_net for ext_net in self.neutron.list_networks()['networks'] if ext_net['router:external']][0]
                            logger.debug("external network id: %s" % ext_net["id"])
                            body_value = {"network_id": ext_net['id']}
                            gateway_result = self.neutron.add_gateway_router(router=router_result['router']['id'], body=body_value)
                            logger.debug(gateway_result)
                            
                            router_id = router_result['router']['id']
                        
                        body_value = {'subnet_id': subnet_result["subnets"][0]['id']}
                        interface_result = self.neutron.add_interface_router(router=router_id, body=body_value)
                        logger.debug(interface_result)

                    logger.info("network successfully created and configured")
                except Exception as e:
                    logger.error(e)

        logger.info("allocating resources...")
        new_server = self.nova.servers.create(
            name=extended_name,
            image=self.nova.glance.find_image(image_name),
            flavor=self.nova.flavors.find(name=flavor),
            security_groups=["ob_sec_group"],
            nics=[{'net-id': networks[selected_networks["wan"]]["id"]}, {'net-id': networks[selected_networks["lan"]]["id"]}]
          )
        id = new_server.id
        logger.info("pfSense created, id: {}".format(id))

        openstack_build_timeout = float(240.0)  # seconds
        wait_quantum = 0.3  # seconds
        current_attempt = 0
        max_attempts = openstack_build_timeout / wait_quantum

        while True:
            new_server = self.nova.servers.get(id)
            status = new_server.status

            if status != "BUILD":
                break
            time.sleep(wait_quantum)
            current_attempt += 1

            if current_attempt > max_attempts:
                raise OpenStackDeploymentError(message="Timeout in openstack server building process")

        lan_ip_dict = new_server.networks
        logger.debug(lan_ip_dict)
        logger.info("pfSense instance is ACTIVE")
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
            new_server.add_floating_ip(floating_ip_to_add, lan_ip_dict[selected_networks['wan']][0])
            logger.debug("floating ip {0} added".format(floating_ip_to_add))
        else:
            #TODO add_floating_ip is deprecated. instead, use update_floatingip
            # see: https://github.com/openstack/python-neutronclient/blob/master/neutronclient/v2_0/client.py
            # and: https://developer.openstack.org/api-ref/network/v2/
            try:
                ip = self.allocate_floating_ips(ext_net, 1)[0]
                new_server.add_floating_ip(ip, lan_ip_dict[selected_networks['wan']][0])
                OpenStackDeploymentError(message="Unable to associate Floating IP")
            except Exception as e:
                logger.error("Unable to associate floating ip to pfsense")

        return {"id" : id, "ip" : floating_ip_to_add, "lan_ip": lan_ip_dict[selected_networks['lan']][0]}

    def allocate_floating_ips(self, ext_net, fip_num=0):
        body = {
            "floatingip": {
                "floating_network_id": ext_net['id']
            }
        }
        ip_list = []

        for i in range(fip_num):
            try:
                ip_list.append(self.neutron.create_floatingip(body=body))
            except IpAddressGenerationFailureClient as e:
                logger.error("Not able to allocate floatingips :(")
                raise OpenstackClientError("Not able to allocate floatingips :(")

        return ip_list

    def delete_server(self, server_id):
        logger.debug("Deleting server {0}".format(server_id))
        try:
            s = self.nova.servers.get(server_id)
            logger.debug(s)
            s.delete()
        except Exception as e:
            logger.error(e)

    def list_server(self, project_id):
        if not self.nova:
            self.set_nova(project_id)
        all_servers = self.nova.servers.list(search_opts={'all_tenants': 1})
        return [s for s in all_servers if (hasattr(s, 'project_id') and s.project_id == project_id) or (
        hasattr(s, 'tenant_id') and s.tenant_id == project_id)]

    def allow_forwarding(self, server_id):
        try:
            interface_list = self.neutron.list_ports(device_id=server_id)["ports"]
        except Exception as e:
            print(e)
        global ret
        for i in interface_list:
            # ret = neutron.update_port(i["id"], {"port":{"port_security_enabled": False, "security_groups" : []}})
            ret = self.neutron.update_port(i["id"], {"port": {"allowed_address_pairs": [{"ip_address": "0.0.0.0/0", "mac_address": i["mac_address"]}]}})
            logger.debug(ret)

    def upload_image(self, image_name, path):
        # removed visibility property
        #i = self.glance.images.create(name=image_name, disk_format="qcow2", container_format="bare", visibility="public", protected=True)
        i = self.glance.images.create(name=image_name, disk_format="qcow2", container_format="bare", protected=True)
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


