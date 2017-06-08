from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2
from eu.softfire.utils.utils import get_logger
from IPy import IP
from eu.softfire.utils.utils import *
from eu.softfire.exceptions.exceptions import *
import yaml, os
import sqlite3, requests, tarfile

logger = get_logger(config_path)
ip_lists = ["allowed_ips", "denied_ips"]

def add_rule_to_fw(fd, rule) :
    fd.write("curl -X POST -H \"Content-Type: text/plain\" -d '%s' http://localhost:5000/ufw/rules\n" % rule)


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

    def validate_resources(self, user_info=None, payload=None) -> None:

        resource = yaml.load(payload)
        logger.debug("Validating resource %s" % resource)
        '''
        :param payload: yaml string containing the resource definition
        '''
        print(user_info)
        properties = resource["properties"]

        if properties["resource_id"] == "firewall" :
            '''Required properties are already defined in the template'''

            '''Check default_rule value'''
            if properties["default_rule"] == "allow" or properties["default_rule"] == "deny":
                pass
            else :
                message = "default_rule does not contain a valid value"
                logger.info(message)
                # TODO send error to experiment-manager
                raise ResourceValidationError(message=message)


            '''Check syntax'''
            for ip_list in ip_lists :
                if (ip_list in properties) :
                    for ip in properties[ip_list]:
                        #print(ip)
                        try :
                            IP(ip)
                        except ValueError :
                            message = "%s contains invalid values" % ip_list
                            logger.info(message)
                            raise ResourceValidationError(message=message)

            '''Check testbed vale'''
            testbeds = ["fokus", "ericsson", "ads", "dt"]
            if (not properties["want_agent"]) and (not properties["testbed"] in testbeds) :
                message = "testbed does not contain a valid value"
                logger.info(message)
                raise ResourceValidationError(message=message)

            ####### for test ######
            self.provide_resources(user_info, payload)
            ######################
            return

    def provide_resources(self, user_info, payload=None):
        #TODO REMOVE ################
        user_info = {}
        user_info["name"] = "experimenter"
        user_info["id"] = "abababab"
        nsr_id = "test"
        project_id = "761d8b56-b21a-4db2-b4d2-16b05a01bc7e"
        ############################

        logger.info("Requested provide_resources by user %s" % user_info["name"])

        nsr_id = ""

        local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/security-manager")
        tmp_files_path = "%s/tmp/%s" % (local_files_path, random_string(6))
        os.makedirs(tmp_files_path)

        resource = yaml.load(payload)
        properties = resource["properties"]

        '''Download scripts from remote Repository'''
        scripts_url = "%s/%s.tar" % (self.get_config_value("remote-files", "url"), properties["resource_id"])
        tar_filename = "%s/%s.tar" % (tmp_files_path, properties["resource_id"])


        r = requests.get(scripts_url, stream=True)
        with open(tar_filename, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)

        tar = tarfile.open(name=tar_filename, mode="r")
        tar.extractall(path=tmp_files_path)
        tar.close()

        response = []
        if properties["resource_id"] == "firewall" :

            '''Modify scripts with custom configuration'''
            ufw_script = "%s/scripts/ufw.sh" % tmp_files_path
            with open(ufw_script, "a") as fd:
                '''Set default rule'''
                add_rule_to_fw(fd, "default %s" % properties["default_rule"])

                '''Set rules for list of IPs'''
                for ip_list in ip_lists :
                    if ip_list in properties:
                        for ip in properties[ip_list]:
                            if ip_list == "allowed_ips" :

                                rule = "allow from %s" % ip
                            else :
                                rule = "deny from %s" % ip
                            add_rule_to_fw(fd, rule)

                #if properties["logging"] == "True" :
                    '''Configure logging to send log messages to <collector_ip>'''
                    index = ""
                    collector_ip = ""

            tar = tarfile.open(name=tar_filename, mode='w')

            if properties["want_agent"]  :
                '''Prepare .tar with custom scripts'''

                tar.add('%s/scripts' % tmp_files_path, arcname='')
                tar.close()
                #TODO send link to the user to download her scripts
            else :
                #TODO add testbed to descriptor
                '''Prepare VNFPackage'''
                tar.add('%s' % tmp_files_path, arcname='')
                tar.close()
                # TODO deploy VM on the specified testbed and send back IP address
                try :
                    floating_ip = deploy_package(path=tar_filename, project_id=project_id)
                except Exception as e :
                    #TODO Fix
                    logger.error(e)

        # TODO store reference between resource and user
        conn = sqlite3.connect('%s/security-manager.db' % local_files_path)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS resources
                        (username, nsr_id, tmp_folder)''')
        query = "INSERT INTO resources (username, nsr_id, tmp_folder) VALUES ('%s', '%s', '%s')" % (user_info["id"], nsr_id, tmp_files_path)
        logger.debug("Executing %s" % query)

        ################
        query = "DELETE FROM resources WHERE username = '%s'" % user_info["id"]
        ################
        cur.execute(query)
        conn.commit()
        conn.close()

        response.append("{\"ip\": \"prova\"}")
        '''
        Return an array of JSON strings with information about the resources
        '''
        return response

    def _update_status(self) -> dict:
        '''Update the status of the experiments in case of value change'''
        return dict()

    def release_resources(self, user_info, payload=None):
        logger.debug(payload)
        return
        logger.info("Requested release_resources by user %s" % user_info["name"])
        #TODO check on the properties defined in the payload
        return
