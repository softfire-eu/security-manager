import requests
import shutil
import sqlite3
import tarfile
import yaml
from IPy import IP
from sdk.softfire.manager import AbstractManager
from concurrent.futures import ThreadPoolExecutor

from eu.softfire.sec.exceptions.exceptions import *
from eu.softfire.sec.utils.utils import *

logger = get_logger(config_path, __name__)
ip_lists = ["allowed_ips", "denied_ips"]


class SecurityManager(AbstractManager):
    def __init__(self, config_path):
        super(SecurityManager, self).__init__(config_path)
        self.local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/security-manager")
        self.resources_db = '%s/security-manager.db' % self.local_files_path

        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS elastic_indexes (username, elastic_index, dashboard_id)''')
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS resources (username, resource_id, project_id, nsr_id, nsd_id, random_id)''')

        conn.commit()
        conn.close()

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
        result.append(
            messages_pb2.ResourceMetadata(resource_id=resource_id, description=description, cardinality=cardinality,
                                          node_type=node_type, testbed=testbed))
        return result

    def validate_resources(self, user_info=None, payload=None) -> None:

        resource = yaml.load(payload)
        logger.debug("Validating resource %s" % resource)
        '''
        :param payload: yaml string containing the resource definition
        '''
        print(user_info)
        properties = resource["properties"]

        if properties["resource_id"] == "firewall":
            '''Required properties are already defined in the template'''

            '''Check default_rule value'''
            if properties["default_rule"] == "allow" or properties["default_rule"] == "deny":
                pass
            else:
                message = "default_rule does not contain a valid value"
                logger.info(message)
                raise ResourceValidationError(message=message)

            '''Check syntax'''
            for ip_list in ip_lists:
                if (ip_list in properties):
                    for ip in properties[ip_list]:
                        # print(ip)
                        try:
                            IP(ip)
                        except ValueError:
                            message = "%s contains invalid values" % ip_list
                            logger.info(message)
                            raise ResourceValidationError(message=message)

            '''Check testbed value'''
            testbeds = TESTBED_MAPPING.keys()
            # testbeds = get_config("open-baton", "testbeds", config_path)
            if (not properties["want_agent"]) and (
                            not "testbed" in properties or (not properties["testbed"] in testbeds)):
                message = "testbed does not contain a valid value"
                logger.info(message)
                raise ResourceValidationError(message=message)

            return

    def provide_resources(self, user_info, payload=None):
        logger.debug("user_info: type: %s, %s" % (type(user_info), user_info))
        logger.debug("payload: %s" % payload)

        # TODO REMOVE
        try:
            # TODO check param name
            username = user_info.name
        except Exception:
            username = "experimenter"

        # TODO REMOVE
        try:
            # TODO check param name
            project_id = user_info.ob_project_id
            logger.debug("Got project id %s" % project_id)
            default_project_id = get_config("open-baton", "default-project", config_path)
            if project_id == "":
                project_id = default_project_id
        except Exception:
            project_id = default_project_id
        # Hardcoded to test interacion with Open baton. Should be sent by the experiment-manager

        logger.info("Requested provide_resources by user %s" % username)

        nsr_id = ""

        nsd_id = ""

        random_id = random_string(15)

        tmp_files_path = "%s/tmp/%s" % (self.local_files_path, random_id)
        logger.debug("Store tmp files in folder %s" % tmp_files_path)
        os.makedirs(tmp_files_path)

        resource = yaml.load(payload)
        properties = resource["properties"]

        '''Download scripts from remote Repository'''
        scripts_url = "%s/%s.tar" % (self.get_config_value("remote-files", "url"), properties["resource_id"])
        tar_filename = "%s/%s.tar" % (tmp_files_path, properties["resource_id"])

        print(scripts_url)
        r = requests.get(scripts_url, stream=True)
        with open(tar_filename, 'wb') as fd:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)

        tar = tarfile.open(name=tar_filename, mode="r")
        tar.extractall(path=tmp_files_path)
        tar.close()

        response = {}
        resource_id = properties["resource_id"]
        if resource_id == "firewall":

            '''Modify scripts with custom configuration'''
            ufw_script = "%s/scripts/ufw.sh" % tmp_files_path
            with open(ufw_script, "a") as fd:
                '''Set default rule'''
                add_rule_to_fw(fd, "default %s" % properties["default_rule"])

                if properties["logging"]:
                    fd.write("ufw logging low\n")

                '''Set rules for list of IPs'''
                for ip_list in ip_lists:
                    if ip_list in properties:
                        for ip in properties[ip_list]:
                            if ip_list == "allowed_ips":

                                rule = "allow from %s" % ip
                            else:
                                rule = "deny from %s" % ip
                            add_rule_to_fw(fd, rule)

            if properties["logging"]:
                collector_ip = get_config("log-collector", "ip", config_path)
                elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
                dashboard_template = get_config("log-collector", "dashboard-template", config_path)
                kibana_port = get_config("log-collector", "kibana-port", config_path)
                logger.debug("Configuring logging")

                '''Selection of the Elasticsearch Index'''
                conn = sqlite3.connect(self.resources_db)
                cur = conn.cursor()

                query = "SELECT elastic_index, dashboard_id FROM elastic_indexes WHERE username='%s'" % (username)
                res = cur.execute(query)
                row = res.fetchone()
                dashboard_path = "%s/dashboard.html" % tmp_files_path
                try:
                    elastic_index = row[0]
                    dashboard_id = row[1]
                    store_kibana_dashboard(dashboard_path, collector_ip, kibana_port, dashboard_id)
                except TypeError:
                    logger.debug("Creating new index and dashboard on Elasticsearch")
                    elastic_index = random_string(15)
                    dashboard_id = random_string(15)
                    try:
                        with ThreadPoolExecutor(max_workers=1) as executor :
                            future = executor.submit(create_kibana_dashboard, elastic_index,dashboard_path, dashboard_id)
                            future.result(10)
                    except Exception:
                        dashboard_id = ""
                    query = "INSERT INTO elastic_indexes (username, elastic_index, dashboard_id) VALUES ('%s', '%s', '%s')" % \
                            (username, elastic_index, dashboard_id)
                    logger.debug("Executing %s" % query)
                    cur.execute(query)
                    conn.commit()

                conn.close()

                collector_ip = get_config("log-collector", "ip", config_path)
                logstash_port = get_config("log-collector", "logstash-port", config_path)

                '''Configure rsyslog to send log messages to <collector_ip>'''
                logger.debug("Configuring logging to %s" % collector_ip)
                rsyslog_conf = "%s/scripts/10-softfire.conf" % tmp_files_path
                conf = ""
                with open(rsyslog_conf) as fd_old:
                    for line in fd_old:
                        conf += line.replace("test", elastic_index)
                conf += '''\nif ($msg contains "[UFW ") then { 
                action(type="omfwd" target="%s" port="%s" template="softfireFormat")
                }\n''' % (collector_ip, logstash_port)
                with open(rsyslog_conf, "w") as fd_new:
                    fd_new.write(conf)

                link = "http://%s:%s/dashboard/%s" % (get_config("system", "ip", config_file_path=config_path),
                                                      get_config("api", "port", config_file_path=config_path),
                                                      random_id)
                response["log_dashboard_link"] = link
                # response.append(json.dumps({"log_dashboard_link": link}))

            tar = tarfile.open(name=tar_filename, mode='w')

            if properties["want_agent"]:
                '''Prepare .tar with custom scripts'''

                tar.add('%s/scripts' % tmp_files_path, arcname='')
                tar.close()

                link = "http://%s:%s/%s/%s" % (get_config("system", "ip", config_file_path=config_path),
                                               get_config("api", "port", config_file_path=config_path),
                                               properties["resource_id"], random_id)
                logger.debug(link)
                response["download_link"] = link
                # response.append(json.dumps({"download_link": link}))
            else:
                vnfd = {}
                with open("%s/vnfd.json" % tmp_files_path, "r") as fd:
                    vnfd = json.loads(fd.read())
                logger.debug(vnfd)
                vnfd["name"] += ("-%s" % random_id)
                vnfd["type"] = vnfd["name"]

                vnfd["vdu"][0]["vimInstanceName"] = ["vim-instance-%s" % properties["testbed"]]

                '''
                
                vnfd["vdu"][0]["vm_image"][0] = properties["os_image_name"]
                
                '''
                if "lan_name" in properties :
                    vnfd["vdu"][0]["vnfc"][0]["connection_point"][0]["virtual_link_reference"] = properties["lan_name"]
                    vnfd["virtual_link"][0]["name"] = properties["lan_name"]

                # TODO set network. To pe added also in the resource definition

                logger.debug(vnfd["name"])
                logger.debug("Prepared VNFD: %s" % vnfd)
                with open("%s/vnfd.json" % tmp_files_path, "w") as fd:
                    fd.write(json.dumps(vnfd))
                '''Prepare VNFPackage'''
                tar.add('%s' % tmp_files_path, arcname='')
                tar.close()
                nsr_details = {}
                logger.debug("Open Baton project_id: %s" % project_id)
                try:
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(deploy_package, tar_filename, project_id)
                        return_val = future.result(20)
                    nsr_details = json.loads(return_val)
                    nsr_id = nsr_details["id"]
                    nsd_id = nsr_details["descriptor_reference"]
                    response["NSR Details"] = nsr_details
                except Exception as e :
                    message = "Error deploying the Package on Open Baton: %s" % e
                    logger.error(message)
                    nsr_id = "ERROR"
                    response["NSR Details"] = "ERROR: %s" % message


        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        query = "INSERT INTO resources (username, resource_id, project_id, nsr_id, nsd_id, random_id, elastic_index) VALUES ('%s',  '%s', '%s', '%s', '%s', '%s', '%s')" % \
                (username, resource_id, project_id, nsr_id, nsd_id, random_id, elastic_index)
        logger.debug("Executing %s" % query)

        cur.execute(query)
        conn.commit()
        conn.close()

        '''
        Return an array of JSON strings with information about the resources
        '''
        logger.debug("Responding %s" % json.dumps(response))
        return [json.dumps(response)]

    def _update_status(self) -> dict:
        #logger = get_logger(config_path)
        logger.debug("Checking status update")
        result = {}
        try :
            conn = sqlite3.connect(self.resources_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            query = "SELECT * FROM resources AS r JOIN elastic_indexes AS e ON r.username = e.username"
            res = cur.execute(query)
            rows = res.fetchall()
        except Exception as e :
            logger.error("Problem reading the Resources DB: %s" % e)
            conn.close()
            return result

        for r in rows:
            s = {}
            '''nsr_id and project_id could be empty with want_agent'''
            nsr_id = r["r.nsr_id"]
            project_id = r["r.project_id"]
            username = r["r.username"]
            elastic_index = r["e.elastic_index"]
            random_id = r["r.random_id"]
            resource_id = r["r.resource_id"]

            '''Repush index-pattern'''
            if elastic_index != "":
                link = "http://%s:%s/dashboard/%s" % (get_config("system", "ip", config_file_path=config_path),
                                                      get_config("api", "port", config_file_path=config_path),
                                                      random_id)
                s["dashboard_log_link"] = link
                try:
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(push_kibana_index, elastic_index)
                        future.result(5)

                except Exception as e:
                    logger.error("Problem contacting the log collector: %s" % e)
                    s["dashboard_log_link"] = "ERROR"

            if nsr_id == "":
                link = "http://%s:%s/%s/%s" % (get_config("system", "ip", config_file_path=config_path),
                                               get_config("api", "port", config_file_path=config_path), resource_id,
                                               random_id)
                s["download_link"] = link

            elif nsr_id == "ERROR" :
                s["status"] = "Error deploying the Package on Open Baton"

            else:
                '''Open Baton resource'''
                logger.debug("Checking resource nsr_id: %s" % nsr_id)

                try:
                    agent = ob_login(project_id)
                    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
                    ob_resp = nsr_agent.find(nsr_id)
                    time.sleep(5)
                    ob_resp = json.loads(ob_resp)
                    logger.debug(ob_resp)

                    s["status"] = ob_resp["status"]
                except Exception as e:
                    logger.error("Error contacting Open Baton to check resource status, nsr_id: %s\n%s" % (nsr_id, e))
                    s["status"] = "ERROR checking status"

                print(s)
                if s["status"] == "ACTIVE":
                    s["ip"] = ob_resp["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]["ip"]
                    s["api_url"] = "http://%s:5000" % s["ip"]
                    try:
                        api_resp = requests.get(s["api_url"])
                        logger.debug(api_resp)
                    except Exception:
                        s["status"] == "VM is running but API are unavailable"

            if username not in result.keys():
                result[username] = []
            result[username].append(json.dumps(s))
        logger.debug("Result: %s" % result)
        return result

    def release_resources(self, user_info=None, payload=None):
        # TODO REMOVE
        try:
            # TODO check param name
            username = user_info.name
        except Exception:
            username = "experimenter"

        logger.info("Requested release_resources by user %s" % username)
        logger.debug("Arrived release_resources\nPayload: %s" % payload)

        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources WHERE username = '%s'" % username
        res = cur.execute(query)
        rows = res.fetchall()
        for r in rows:
            if r["nsr_id"] != "" and r["nsr_id"] != "ERROR":
                try:
                    delete_ns(nsr_id=r["nsr_id"], nsd_id=r["nsd_id"], project_id=r["project_id"])
                except Exception as e:
                    logger.error("Problem contacting Open Baton: " % e)

            file_path = "%s/tmp/%s" % (self.local_files_path, r["random_id"])
            try:
                shutil.rmtree(file_path)
            except FileNotFoundError:
                logger.error("FileNotFoud: %s" % file_path)

        query = "DELETE FROM resources WHERE username = '%s'" % username
        cur.execute(query)

        conn.commit()
        conn.close()

        return
