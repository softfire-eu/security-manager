from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2
from sdk.softfire.utils import get_config
from eu.softfire.utils.utils import get_logger
from IPy import IP
from eu.softfire.utils.utils import config_path
import yaml
import sqlite3, requests

logger = get_logger(config_path)

class SecurityManager(AbstractManager):


    def refresh_resources(self, user_info):
        return None

    def create_user(self, username, password):
        print("Arrivata create_user")
        user_info = messages_pb2.UserInfo(
            name=username,
            password=password,
            ob_project_id='id',
            testbed_tenants={}
        )

        return user_info

    def list_resources(self, user_info=None, payload=None):
        logger.debug("List resources")
        resource_id = "firewall"
        description = "This resource permits to deploy a firewall. You can deploy it as a standalone VM, " \
                      "or you can use it as an agent directly installed on the machine that you want to protect. " \
                      "This resource offers the functionalities of UFW (https://help.ubuntu.com/community/UFW) and can be easily " \
                      "configured by means of a Rest API.\nMore information at http://docs.softfire.eu/security-manager/"
        cardinality = -1
        testbed = messages_pb2.ANY
        node_type = "SecurityResource"
        result = []
        result.append(messages_pb2.ResourceMetadata(resource_id=resource_id, description=description, cardinality=cardinality, node_type=node_type, testbed=testbed))
        return result

    def validate_resources(self, user_info=None, payload=None):
        resource = yaml.load(payload)
        logger.debug("Validating resource %s" % resource)
        '''
        :param payload: yaml string containing the resource definition
        '''
        print(user_info)
        #TODO send errors to experiment manager
        properties = resource["properties"]


        if properties["resource_id"] == "firewall" :
            '''Required properties are already defined in the template'''

            '''Check default_rule value'''
            if properties["default_rule"] == "allow" or properties["default_rule"] == "deny":
                pass
            else :
                logger.info("default_rule does not contain a valid value")
                # TODO send error to experiment-manager
                return

            '''Check syntax'''
            ip_lists = ["allowed_ips", "denied_ips"]
            for ip_list in ip_lists :
                if (ip_list in properties) :
                    for ip in properties[ip_list]:
                        #print(ip)
                        try :
                            IP(ip)
                        except ValueError :
                            logger.info("%s contains unvalid values" % ip_list)
                            #TODO send error to experiment-manager
                            return

            '''Check testbed vale'''
            testbeds = ["fokus", "ericsson", "ads", "dt"]
            if (not properties["testbed"] in testbeds) and (properties["want_agent"] == "False") :
                #TODO send error to experiment-manager
                logger.info("testbed does not contain a valid value")
                return

            return messages_pb2.ResponseMessage(result=-1)

    def provide_resources(self, user_info, payload=None):
        logger.info("Requested provide_resources by user %s" % user_info["name"])

        local_files_path = self.get_config_value("files", "path", "/etc/softfire/security-manager")

        resource = yaml.load(payload)
        properties = resource["properties"]

        '''Download scripts from remote Repository'''
        scripts_url = "%s/%s.tar" % (self.get_config_value("remote-files", "url"), properties["resource_id"])
        #TODO Check if can be done better
        filename = "%s/tmp/%s" % (local_files_path, properties["resource_id"])

        r = requests.get(scripts_url, stream=True)
        with open(filename, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)

        response = {}
        if properties["resource_id"] == "firewall" :
            #TODO modify scripts with custom configuration

            if properties["want_agent"] == "True" :
                #TODO send link to the user to download her scripts
                response["scripts_url"] = "%s/%s/scripts.tar" % (self.get_config_value("remote-files", "url"), properties["resource_id"])
                pass
            else :
                # TODO deploy VM on the specified testbed and send back IP address
                nsr_id = ""
                # TODO store reference between resource and user
                conn = sqlite3.connect('%s/security-manager.db' % files_path)
                cur = conn.cursor()
                cur.execute('''CREATE TABLE IF NOT EXISTS resources
                                (username, nsr_id)''')
                cur.execute("INSERT INTO resources (username, nsr_id) VALUES (%s, %s)" % (user_info["id"], nsr_id))
                conn.commit()
                conn.close()

        return messages_pb2.ProvideResourceResponse(resources="content")

    def release_resources(self, user_info, payload=None):
        logger.info("Requested release_resources by user %s" % user_info["name"])
        #TODO check on the properties defined in the payload
        return None