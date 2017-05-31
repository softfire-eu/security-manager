from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2
from eu.softfire.utils.utils import get_logger
from IPy import IP
import yaml

logger = get_logger()

class SecurityManager(AbstractManager):

    def __init__(self):
        logger.info("Creato SecurityManager")

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
        logger.info("List resources")
        #TODO
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
        logger.info("Validate resources")
        '''
        :param payload: yaml string containing the resource definition
        '''
        print(user_info)
        resource = yaml.load(payload)
        #TODO send errors to experiment manager
        properties = resource["properties"]
        if properties["resource_id"] == "firewall" :
            '''Required properties are already defined in the template'''

            '''Check default_rule value'''
            if properties["default_rule"] == "allow" or properties["default_rule"] == "deny":
                pass
            else :
                print("ERROR")
                # TODO send error to experiment-manager

            '''Check syntax'''
            ip_lists = ["allowed_ips", "denied_ips"]
            for ip_list in ip_lists :
                if (ip_list in properties) :
                    for ip in properties[ip_list]:
                        print(ip)
                        try :
                            IP(ip)
                        except ValueError :
                            print("ERROR")
                            #TODO send error to experiment-manager

            '''Check testbed vale'''
            testbeds = []
            if properties["testbed"] not in testbeds :
                #TODO send error to experiment-manager
                pass

            return messages_pb2.ResponseMessage(result=-1)

    def provide_resources(self, user_info, payload=None):
        print("Provide resources")

        return messages_pb2.ProvideResourceResponse(resources="content")

    def release_resources(self, user_info, payload=None):
        print("Release Resources")
        #TODO check on the properties defined in the payload
        return None