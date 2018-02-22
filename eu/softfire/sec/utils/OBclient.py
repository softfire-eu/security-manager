from org.openbaton.cli.agents.agents import OpenBatonAgentFactory
from eu.softfire.sec.utils.utils import *
import re

logger = get_logger(config_path, __name__)

class OBClient :

    def __init__(self, project_id):
        ob_conf = get_config_parser(config_path)["open-baton"]

        self.project_id = project_id
        '''Open Baton Login'''
        self.agent = OpenBatonAgentFactory(nfvo_ip=ob_conf["ip"], nfvo_port=int(ob_conf["port"]),
                                      https=(ob_conf["https"] == "True"), version=int(ob_conf["version"]),
                                      username=ob_conf["username"], password=ob_conf["password"],
                                      project_id=project_id)


    def deploy_package(self, path, body : dict={}, resource_type=None):
        logger.debug("Started deploy_package")
        '''Open Baton Login'''
        agent = self.agent
        project_id = self.project_id

        '''Upload the VNFP'''
        vnfp_agent = agent.get_vnf_package_agent(project_id=project_id)
        vnfp = vnfp_agent.create(path)

        logger.debug("vnfd created. %s" % vnfp) 

        '''Create and upload the NSD'''
        # nsd_file_path = "etc/resources/nsd-fw.json"

        remote_url = get_config("remote-files", "url", config_path)

        # r = requests.get("%s/nsd-fw.json" % remote_url)
        logger.debug("requesting NSD for type: %s" % resource_type)
        logger.debug("remote url: %s" % remote_url)
        r = requests.get("%s/nsd-%s.json" % (remote_url, resource_type))

        nsd = json.loads(r.text)

        nsd_agent = agent.get_ns_descriptor_agent(project_id)
        '''
		nsd = {}
		with open(nsd_file_path, "r") as fd:
			nsd = json.load(fd)
		'''
        nsd["vnfd"] = [{"id": vnfp["id"]}]
        virtual_links = [{"name": "softfire-internal"}]
        nsd["vld"] = virtual_links

        logger.debug(nsd)
#        for k in nsd.keys():
#            print("%s:%s" % (k, nsd[k]))

#	nsd_dummy = {
#                "name": "NSD Security Firewall",
#                "version": "softfire_version",
#                "vendor": "Security Reply",
#                "vnfd": ,
#                "vld": virtual_links}

        with open("/tmp/nsd.json", "w") as nsd_f:
            nsd_f.write(json.dumps(nsd))
        nsd = nsd_agent.create(json.dumps(nsd))

        '''Deploy of the NSR'''
        nsr_agent = agent.get_ns_records_agent(project_id=project_id)
        nsr = nsr_agent.create(nsd["id"], json.dumps(body))

        nsr_details = nsr_agent.find(nsr["id"])
 #       logger.debug(nsr_details)

        return nsr_details

    def delete_ns(self, nsr_id, nsd_id):
        logger.debug("Deleting NSR {0}".format(nsr_id))
        agent = self.agent
        project_id = self.project_id
        nsr_agent = agent.get_ns_records_agent(project_id=project_id)
        nsr_agent.delete(nsr_id)

        nsd_agent = agent.get_ns_descriptor_agent(project_id)
        time.sleep(5)  # Give Open Baton time to process the request
        nsd_agent.delete(nsd_id)



    def import_key(self, ssh_pub_key, name):
        agent = self.agent
        project_id = self.project_id
        logger.debug("project id: %s" % self.project_id)
        key_agent = agent.get_key_agent(project_id)
        for key in json.loads(key_agent.find()):
            print(key)
            if key.get('name') == name:
                key_agent.delete(key.get('id'))
                break
        key_agent.create(json.dumps({"name": name, "projectId": project_id, "publicKey": ssh_pub_key}))
