from sdk.softfire.manager import AbstractManager

from IPy import IP
from eu.softfire.utils.utils import *
from eu.softfire.exceptions.exceptions import *
import yaml, os
import sqlite3, requests, tarfile, shutil


logger = get_logger(config_path)
ip_lists = ["allowed_ips", "denied_ips"]


class SecurityManager(AbstractManager):

    def __init__(self, config_path):
        super(SecurityManager, self).__init__(config_path)
        self.local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/security-manager")
        self.resources_db = '%s/security-manager.db' % self.local_files_path

    def refresh_resources(self, user_info):
        return None

    def create_user(self, user_info):
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

        nsd_id = ""
        log_dashboard_url = ""

        random_id = random_string(15)

        tmp_files_path = "%s/tmp/%s" % (self.local_files_path, random_id)
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


            if properties["logging"] :
                logger.debug("Configuring logging")
                '''Configure logging to send log messages to <collector_ip>'''
                elastic_index = random_id
                collector_ip = get_config("log-collector", "ip", config_path)
                logstash_port = get_config("log-collector", "logstash-port", config_path)
                rsyslog_conf = "%s/scripts/10-softfire.conf" % tmp_files_path
                conf = ""
                with open(rsyslog_conf) as fd_old :
                    for line in fd_old :
                        conf += line.replace("test", elastic_index)

                print(collector_ip)
                conf += '''\nif ($msg contains "[UFW ") then { 
                action(type="omfwd" target="%s" port="%s" template="softfireFormat")
                }\n''' % (collector_ip, logstash_port)

                with open(rsyslog_conf, "w") as fd_new:
                    fd_new.write(conf)
                elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
                dashboard_template = get_config("log-collector", "dashboard-template", config_path)
                kibana_port = get_config("log-collector", "kibana-port", config_path)

                log_dashboard_url = ""

            tar = tarfile.open(name=tar_filename, mode='w')

            if properties["want_agent"]  :
                '''Prepare .tar with custom scripts'''

                tar.add('%s/scripts' % tmp_files_path, arcname='')
                tar.close()

                link = "http://%s:%s/%s/%s" % (get_config("system", "ip", config_file_path=config_path), get_config("api", "port", config_file_path=config_path), properties["resource_id"], random_id)
                response.append(json.dumps({"download_link" : link}))
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

        # TODO store reference between resource and user. ADD status, api-ip, dashboard_url
        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS resources (username, project_id, nsr_id, nsd_id, random_id, log_dashboard_url)''')
        query = "INSERT INTO resources (username, project_id, nsr_id, nsd_id, random_id, log_dashboard_url) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')" % \
                (user_info.name, project_id, nsr_id, nsd_id, random_id, log_dashboard_url)
        logger.debug("Executing %s" % query)

        cur.execute(query)
        conn.commit()
        conn.close()

        '''
        Return an array of JSON strings with information about the resources
        '''
        return response

    def _update_status(self) -> dict:
        logger.debug("Checking status update")
        result = {}
        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources"
        res = cur.execute(query)
        rows = res.fetchall()
        for r in rows:
            #TODO nsr_id e project_id could be empty with want_agent
            nsr_id = r["nsr_id"]
            project_id = r["project_id"]
            username = r["username"]
            #TODO FIX THESE
            #download_link = r["download_link"]
            #dashboard_url = r["dashboard_url"]
            #api_url = r["api_url"]

            if nsr_id == "" :
                return ""


            else :
                '''Open Baton resource'''
                logger.debug("Checking resource nsr_id: %s" % nsr_id)

                try :
                    agent = ob_login(project_id)
                    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
                    ob_resp = nsr_agent.find(nsr_id)
                    time.sleep(5)
                    ob_resp = json.loads(ob_resp)
                    logger.debug(ob_resp)
                except Exception as e :
                    logger.error("Error contacting Open Baton to validate resource nsr_id: %s\n%s" % (nsr_id, e))

                s = {}
                s["status"] = ob_resp["status"]

                print(s)
                #if ACTIVE
                if s["status"] == "ACTIVE" :
                    s["ip"] = ob_resp["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]["ip"]
                    s["api_url"] = "http://%s:5000" % s["ip"]
                    try :
                        api_resp = requests.get(s["api_url"])
                        logger.debug(api_resp)
                    except Exception:
                        s["status"] == "VM is running but API are unavailable"

            if username not in result.keys():
                result[username] = []
            result[username].append(json.dumps(s))
        return result


    def release_resources(self, user_info, payload=None):
        logger.info("Requested release_resources by user %s" % user_info.name)
        logger.debug("Arrived release_resources\nPayload: %s" % payload)

        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources WHERE username = '%s'" % user_info.name
        res = cur.execute(query)
        rows = res.fetchall()
        for r in rows:
            delete_ns(nsr_id=r["nsr_id"], nsd_id=r["nsd_id"], project_id=r["project_id"])
            shutil.rmtree("%s/tmp/%s" % (self.local_files_path, r["random_id"]))

        query = "DELETE FROM resources WHERE username = '%s'" % user_info.name
        ################
        cur.execute(query)
        conn.commit()
        conn.close()

        #TODO delete folders
        return
