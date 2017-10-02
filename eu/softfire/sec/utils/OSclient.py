import eu.softfire.sec.utils.utils as utils
import json

class OSclient :

	def __init__(self, testbed):
		os_credentials_file = utils.get_config_parser(utils.config_path)["open-baton"]
		with open(os_credentials_file) as credentials_file:
			credentials = json.load(credentials_file)
		testbed_info = credentials[testbed]
		self.username = testbed_info["username"]
		self.password = testbed_info["password"]
		self.url = testbed_info["auth_url"]
		self.ext_net = testbed_info["ext_net_name"]
		self.api_version = testbed_info["api_version"]
		self.

		return

