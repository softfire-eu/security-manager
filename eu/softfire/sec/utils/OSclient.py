import eu.softfire.sec.utils.utils as utils
from eu.softfire.sec.exceptions.exceptions import OpenStackDeploymentError
import json

from keystoneauth1 import identity
from keystoneauth1 import session
from keystoneauth1 import loading
from novaclient import client as nova_client
from glanceclient import client as glance_client
from neutronclient.v2_0 import client as neutron_client

import bcrypt
import hashlib
import time

logger = utils.get_logger(utils.config_path, __name__)

class OSclient :

	def __init__(self, testbed, exp_username, exp_tenant_id):
		os_credentials_file = utils.get_config("openstack", "credentials-file", utils.config_path)
		with open(os_credentials_file) as credentials_file:
			credentials = json.load(credentials_file)
		testbed_info = credentials[testbed]
		self.admin_username = testbed_info["username"]
		self.password = testbed_info["password"]
		self.auth_url = testbed_info["auth_url"]
		self.ext_net = testbed_info["ext_net_name"]
		self.api_version = testbed_info["api_version"]
		self.domain_name = testbed_info["user_domain_name"]
		self.exp_username = exp_username
		self.exp_tenant_id = exp_tenant_id

		#self.logger = utils.get_logger(utils.config_path, __name__)

		if self.api_version == 2:
			OSloader = loading.get_plugin_loader('password')
			auth = OSloader.load_from_options(
				auth_url=self.auth_url,
				username=self.admin_username,
				password=self.password,
				tenant_name=exp_tenant_id,
			)

		if self.api_version == 3:
			auth = identity.v3.Password(
				auth_url=self.auth_url,
				username=self.admin_username,
				password=self.password,
				project_domain_name=self.domain_name,
				user_domain_name=self.domain_name,
				project_id=exp_tenant_id
			)

		self.os_session = session.Session(auth=auth)

		self.nova = nova_client.Client(2, session=self.os_session)
		self.neutron = neutron_client.Client(session=self.os_session)

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

		networks = self.neutron.list_networks(tenant_id=self.exp_tenant_id)["networks"]
		network_names = [x["name"] for x in networks]
		router_name = 'router' #TODO check conflicts
		net_names = [selected_networks["wan"], selected_networks["lan"]]

		#TODO cambiare tutte le print, mettere log e togliere riferimenti a Zabbix

		for network in net_names:
			if network in network_names:
				logger.debug("network found {}".format(network))
			else:
				logger.debug("network not found, trying to create it")

				kwargs = {'network': {
					'name': network,
					'shared': False,
					'admin_state_up': True
				}}
				logger.debug("Creating net {}".format(network))

				network_ = self.neutron.create_network(body=kwargs)['network']

				logger.debug("net created {}".format(network_))
				rand_num = int(hashlib.sha1(self.exp_username).hexdigest(), base=16) % 254 + 1
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

				router = self.neutron.list_routers(name=router_name, tenant_id=self.exp_tenant_id)["routers"][0]
				router_id = router['id']
				body_value = {
					'subnet_id': subnet["subnets"][0]['id'],
				}

				self.neutron.add_interface_router(router=router_id, body=body_value)

				logger.debug("network successfully created and configured")

		new_server = self.nova.servers.create(
			name=extended_name,
			image=self.nova.glance.find_image(image_name),
			flavor=self.nova.flavors.find(name=flavor),
			nics=[{'net-id': self.neutron.list_networks(tenant_id=self.exp_tenant_id, name=n)["networks"][0]["id"]} for n in
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
			if ip["fixed_ip_address"] is None and ip_project_id_ == self.exp_tenant_id:
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
		interface_list = self.neutron.list_ports(device_id=server_id)["ports"]
		for i in interface_list:
			# ret = neutron.update_port(i["id"], {"port":{"port_security_enabled": False, "security_groups" : []}})
			self.neutron.update_port(i["id"], {
				"port": {"allowed_address_pairs": [{"ip_address": "0.0.0.0/0", "mac_address": i["mac_address"]}]}})
			#self.logger.debug(ret)

if __name__ == "__main__" :
	from eu.softfire.sec.utils.fauxapi_lib import FauxapiLib
	import requests
	import pprint
	from paramiko import SSHClient, AutoAddPolicy
	from scp import SCPClient

	import os

	os.environ["http_proxy"] = ""

	testbed = "reply"
	username = "daniele"
	tenant_id = "e9b85df7d3dc4f50b9dfb608df270533"

	openstack = OSclient(testbed, username, tenant_id)
	openstack.nova.glance.find_image("pfsense-softfire")
	try :
		ret = openstack.deploy_pfSense({ "wan" : "my_personal", "lan" : "test" })
	except Exception as e :
		print(e)

	pf_sense_ip = ret["ip"]
	pf_sense_id = ret["id"]

	openstack.allow_forwarding(pf_sense_id)

	# TODO store in DataBase
	# TODO asynchronous tasks?

	fauxapi_apikey = utils.get_config("pfsense", "fauxapi-apikey",utils.config_path, "PFFAsecuritymanager")
	fauxapi_apisecret = utils.get_config("pfsense", "fauxapi-apisecret", utils.config_path, "MIE3ev08qfaCLT9Ga51pDtYNzA84vuRv5CIpdHm80pPqlxzR5Cm4ByjxdcmH")

	api = FauxapiLib(pf_sense_ip, fauxapi_apikey, fauxapi_apisecret, debug=True)

	reachable = False
	while not reachable:
		try:
			config = api.config_get()
			reachable = True
		except requests.exceptions.ConnectionError:
			print("Not Reachable")
			time.sleep(2)

	pprint.pprint(config)
	u = config["system"]["user"][0]
	exp_name = "daniele"  # TODO experimenter name
	password = "password"  # TODO experimenter password

	u["name"] = exp_name
	hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
	bic = hashed.decode()
	u["bcrypt-hash"] = bic

	# TODO Add to config command that stores the FauxAPI Key
	credentials_file = "/etc/fauxapi/credentials.ini"
	local_script_path = "/etc/softfire/security-manager/inject_credentials"
	pfsense_script_path = "/root/inject_credentials"

	ssh = SSHClient()
	ssh.set_missing_host_key_policy(AutoAddPolicy())
	ssh.load_system_host_keys()
	ssh.connect(hostname=pf_sense_ip, port=22, username="root", password="pfsense")
	scp = SCPClient(ssh.get_transport())
	scp.put(files=local_script_path, remote_path=pfsense_script_path)

	# TODO setup right api-key
	apisecret_value = utils.random_string(60)
	config["system"]["shellcmd"] = [
		"sh {0} {1} {2} {3}".format(pfsense_script_path, credentials_file, exp_name, apisecret_value)]

	pprint.pprint(config)
	time.sleep(10)
	api.config_set(config)
	api.config_reload()
	api.system_reboot()

	time.sleep(300)
	openstack.delete_server(pf_sense_id)


