from sdk.softfire.manager import AbstractManager
from sdk.softfire.grpc import messages_pb2
from eu.softfire.utils.utils import get_logger
from IPy import IP
from eu.softfire.utils.utils import *
from eu.softfire.exceptions.exceptions import *
import yaml, os
import sqlite3, requests, tarfile
from threading import Thread

logger = get_logger(config_path)
ip_lists = ["allowed_ips", "denied_ips"]

def add_rule_to_fw(fd, rule) :
    fd.write("curl -X POST -H \"Content-Type: text/plain\" -d '%s' http://localhost:5000/ufw/rules\n" % rule)

'''
class UpdateStatusThread(Thread):
    def __init__(self, manager):
        Thread.__init__(self)
        self.stopped = False
        self.manager = manager

    def run(self):
        while not self.stopped:
            time.sleep(int(self.manager.get_config_value('system', 'update-delay', '10')))
            if not self.stopped:
                try:
                    self.manager.send_update()
                except Exception as e:
                    logger.error("got error while updating resources: %s " % e.args)

    def stop(self):
		self.stopped = True
'''

class SecurityManager(AbstractManager):

    def __init__(self, config_path):
        super(SecurityManager, self).__init__(config_path)
        local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/security-manager")
        self.resources_db = '%s/security-manager.db' % local_files_path


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
            #self.provide_resources(user_info, payload)
            ######################
            return

    def provide_resources(self, user_info, payload=None):
        logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.debug("payload: %s" % payload)

		#TODO REMOVE
        try :
            #TODO check param name
            project_id = user_info.project_id
        except Exception :
            project_id = "761d8b56-b21a-4db2-b4d2-16b05a01bc7e"
			# Hardcoded to test interacion with Open baton. Should be sent by the experiment-manager

        logger.info("Requested provide_resources by user %s" % user_info.name)

        nsr_id = ""

        local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/security-manager")
        random_id = random_string(6)
        tmp_files_path = "%s/tmp/%s" % (local_files_path, random_id)
        logger.debug("Store tmp files in folder %s" %tmp_files_path)
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
                #TODO add testbed to descriptor & change name/version to avoid conflicts
                vnfd = {}
                with open("%s/vnfd.json" % tmp_files_path, "r") as fd :
                    vnfd = json.loads(fd.read())
                logger.debug(vnfd)
                vnfd["name"] +=  ("-%s" % random_id)
                vnfd["type"] = vnfd["name"]
                logger.debug(vnfd["name"])
                logger.debug("Prepared VNFD: %s" % vnfd)
                with open("%s/vnfd.json" % tmp_files_path, "w") as fd:
                    fd.write(json.dumps(vnfd))
                '''Prepare VNFPackage'''
                tar.add('%s' % tmp_files_path, arcname='')
                tar.close()
                # TODO deploy VM on the specified testbed and send back IP address
                #try :
                nsr_details = json.loads(deploy_package(path=tar_filename, project_id=project_id))
                nsr_id = nsr_details["id"]
                nsd_id = nsr_details["descriptor_reference"]


                response.append(json.dumps(nsr_details))
                #except Exception as e :
                    #TODO Fix
                    #logger.error(e)

        # TODO store reference between resource and user
        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS resources (username, project_id, nsr_id, nsd_id, tmp_folder)''')
        query = "INSERT INTO resources (username, project_id, nsr_id, nsd_id, tmp_folder) VALUES ('%s', '%s', '%s', '%s', '%s')" % \
                (user_info.name, project_id, nsr_id, nsd_id, tmp_files_path)
        logger.debug("Executing %s" % query)

        cur.execute(query)
        conn.commit()
        conn.close()

        '''
        Return an array of JSON strings with information about the resources
        '''
        return response

    '''
    def _update_status(self) -> dict:
        logger.debug("Checking status update")
        result = {}
        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()

        query = "SELECT * FROM resources WHERE username = '%s'" % user_info.name
        res = cur.execute(query)
        rows = res.fetchall()
        for username, nsrs in get_nsrs_to_check().items():
            logger.debug("Checking resources of user %s" % username)
            if len(nsrs):
                ob_client = OBClient(username)
                result[username] = []
                for nsr in nsrs:
                    nsr_new = ob_client.get_nsr(nsr.get('id'))
                    if isinstance(nsr_new, dict):
                        nsr_new = json.dumps(nsr_new)
                    status = json.loads(nsr_new).get('status')
                    result[username].append(nsr_new)

                    # result[username].append(json.dumps(nsr))

    return result
	'''
    def release_resources(self, user_info, payload=None):
        logger.debug("Arrived release_resources\nPayload: %s" % payload)

        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources WHERE username = '%s'" % user_info.name
        res = cur.execute(query)
        rows = res.fetchall()
        for r in rows:
            delete_ns(nsr_id=r["nsr_id"], nsd_id=r["nsd_id"], project_id=r["project_id"])

        query = "DELETE FROM resources WHERE username = '%s'" % user_info.name
        ################
        cur.execute(query)
        conn.commit()
        conn.close()
        logger.info("Requested release_resources by user %s" % user_info.name)
        #TODO check on the properties defined in the payload
        return
