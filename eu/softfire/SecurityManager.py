from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2

class SecurityManager(AbstractManager):

    def __init__(self):
        print("Creato SecurityManager")

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
        print("List resources")
        enc = "utf-8"
        #TODO
        resource_id = "firewall"
        description = "Description"
        cardinality = -1
        testbed = messages_pb2.ANY
        node_type = "SecurityResource"
        result = []
        result.append(messages_pb2.ResourceMetadata(resource_id=resource_id, description=description, cardinality=cardinality, node_type=node_type, testbed=testbed))
        return result

    def validate_resources(self, user_info=None, payload=None):
        print("Validate resources")
        '''
        TODO check on the properties defined in the payload
        :payload yaml string
        '''

    def provide_resources(self, user_info, payload=None):
        print("Provide resources")

        return messages_pb2.ProvideResourceResponse(resources="content")

    def release_resources(self, user_info, payload=None):
        print("Release Resources")
        #TODO check on the properties defined in the payload
        return None