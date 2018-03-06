import shutil, sys, traceback
import tarfile
import yaml
import re
import pexpect
from IPy import IP
from sdk.softfire.manager import AbstractManager
from concurrent.futures import ThreadPoolExecutor
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient
import bcrypt
from idstools import rule

from eu.softfire.sec.exceptions.exceptions import *
from eu.softfire.sec.utils.utils import *
from eu.softfire.sec.utils.fauxapi_lib import FauxapiLib
from eu.softfire.sec.utils.OSclient import OSclient
from eu.softfire.sec.utils.OBclient import OBClient

logger = get_logger(config_path, __name__)
ip_lists = ["allowed_ips", "denied_ips"]

OPENBATONRESOURCES = ["firewall", "suricata"]

resources = {
    "firewall": "This resource permits to deploy a firewall. You can deploy it as a standalone VM, " \
                "or you can use it as an agent directly installed on the machine that you want to protect. " \
                "This resource offers the functionalities of UFW (https://help.ubuntu.com/community/UFW) and can be easily " \
                "configured by means of a Rest API.\nMore information at http://docs.softfire.eu/security-manager/",
    "suricata": "This resource permits to deploy a Suricata NIPS. You can deploy it as a standalone VM, " \
                "or you can use it as an agent directly installed on the machine that you want to protect. " \
                "This resource offers the functionalities of Suricata NIPS (https://suricata-ids.org/).\nMore information at http://docs.softfire.eu/security-manager/",
    "pfsense": "This resource permits to deploy a pfSense VM." \
               "This resource offers the functionalities of pfSense (https://www.pfsense.org/), and " \
               "can be configured by means of a Rest API provided by FauxAPI package (https://github.com/ndejong/pfsense_fauxapi)." \
               "\nMore information at http://docs.softfire.eu/security-manager/"
}


class UpdateStatusThread(Thread):
    def __init__(self, sec_manager):
        Thread.__init__(self)
        self.stopped = False
        self.sec_manager = sec_manager

    def run(self):
        while not self.stopped:
            time.sleep(int(self.sec_manager.get_config_value('system', 'update-delay', '10')))
            if not self.stopped:
                try:
                    self.sec_manager.send_update()
                except Exception as e:
                    traceback.print_exc()
                    if hasattr(e, 'args'):
                        logger.error("got error while updating resources: %s " % e)
                    else:
                        logger.error("got unknown error while updating resources")

    def stop(self):
        self.stopped = True


class SecurityManager(AbstractManager):
    def __init__(self, config_path):
        super(SecurityManager, self).__init__(config_path)
        self.local_files_path = self.get_config_value("local-files", "path", "/etc/softfire/security-manager")
        self.resources_db = '%s/security-manager.db' % self.local_files_path

        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS elastic_indexes (username, elastic_index, dashboard_id)''')
        cur.execute(
            '''CREATE TABLE IF NOT EXISTS resources (username, resource_id, testbed, ob_project_id, ob_nsr_id, ob_nsd_id, random_id, os_project_id, os_instance_id, to_update, disable_port_security, lan_ip, floating_ip)''')

        conn.commit()
        conn.close()

    def refresh_resources(self, user_info):
        return None

    def create_user(self, user_info):
        return user_info

    def list_resources(self, user_info=None, payload=None):
        logger.debug("List resources")

        cardinality = -1
        testbed = messages_pb2.ANY
        node_type = "SecurityResource"
        result = []
        for k, v in resources.items():
            result.append(messages_pb2.ResourceMetadata(resource_id=k, description=v, cardinality=cardinality,
                                                        node_type=node_type, testbed=testbed))

        return result

    def validate_resources(self, user_info=None, payload=None) -> None:
        '''
        :param payload: yaml string containing the resource definition
        '''

        resource = yaml.load(payload)
        logger.debug("Validating resource %s" % resource)
        message = ""
        properties = resource["properties"]
        testbeds = TESTBED_MAPPING.keys()

        valid_testbed = "testbed" in properties and properties["testbed"] in testbeds

        want_agent = properties["resource_id"] in OPENBATONRESOURCES and "want_agent" in properties and properties[
            "want_agent"]
        if not (valid_testbed or want_agent):
            message = "testbed does not contain a valid value"
            logger.info(message)
            raise ResourceValidationError(message=message)

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
                        try:
                            IP(ip)
                        except ValueError:
                            message = "%s contains invalid values" % ip_list
                            logger.info(message)
                            raise ResourceValidationError(message=message)

            return

        if properties["resource_id"] == "suricata" and "rules" in properties:
            for r in properties["rules"]:
                ru = rule.parse(r)
                if not ru:
                    message = "Invalid Suricata rule: %s" % r
                    logger.info(message)
                    raise ResourceValidationError(message=message)

    def provide_resources(self, user_info, payload=None):

        logger.info("Starting providing...")

        resource = yaml.load(payload)
        username = user_info.name

        def print_payload(properties, title=None):
            if title:
                logger.debug("%s:" % title)
            for k in properties.keys():
                if isinstance(properties[k], dict):
                    logger.debug("#" + k)
                    print_payload(properties[k])
                else:
                    logger.debug("%s: %s" % (k,
                                             isinstance(properties[k], str) and len(properties[k]) > 100 and properties[
                                                                                                                 k][
                                                                                                             :30] + "..." +
                                             properties[k][-30:] or properties[k]))

        print_payload(resource, "Resource")

        logger.info("Requested provide_resources by user %s" % username)

        nsr_id = ""
        nsd_id = ""
        ob_project_id = ""
        os_project_id = ""
        os_instance_id = ""
        lan_ip = None
        floating_ip = None
        testbed = ""
        update = False
        disable_port_security = False
        random_id = random_string(15)

        tmp_files_path = "%s/tmp/%s" % (self.local_files_path, random_id)
        logger.debug("Store tmp files in folder %s" % tmp_files_path)
        os.makedirs(tmp_files_path)

        properties = resource["properties"]

        response = {}
        response['random_id'] = random_id
        resource_id = properties["resource_id"]

        if "testbed" in properties:
            testbed = properties["testbed"]
            try:
                os_project_id = user_info.testbed_tenants[TESTBED_MAPPING[testbed]]
            except Exception:
                os_project_id = user_info.os_project_id

        if resource_id in OPENBATONRESOURCES:
            ob_project_id = user_info.ob_project_id
            logger.debug("Got Open Baton project id %s" % ob_project_id)

            open_baton = OBClient(ob_project_id)

            '''Download scripts from remote Repository'''
            scripts_url = "%s/%s.tar" % (self.get_config_value("remote-files", "url"), properties["resource_id"])
            tar_filename = "%s/%s-%s.tar" % (tmp_files_path, properties["resource_id"], random_id)

            r = requests.get(scripts_url, stream=True)
            with open(tar_filename, 'wb') as fd:
                for chunk in r.iter_content(chunk_size=128):
                    fd.write(chunk)

            tar = tarfile.open(name=tar_filename, mode="r")
            tar.extractall(path=tmp_files_path)
            tar.close()

            if "logging" in properties and properties["logging"]:
                logger.info("Configuring logging")
                collector_ip = get_config("log-collector", "ip", config_path)
                elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
                dashboard_template = get_config("log-collector", "dashboard-template", config_path)
                kibana_port = get_config("log-collector", "kibana-port", config_path)
                logger.debug(
                    "LEK_ip:{} - elastic_port:{} - kibana_port:{}".format(collector_ip, elastic_port, kibana_port))

                '''Selection of the Elasticsearch Index'''
                conn = sqlite3.connect(self.resources_db)
                cur = conn.cursor()

                query = "SELECT elastic_index, dashboard_id FROM elastic_indexes WHERE username=?"
                res = cur.execute(query, (username,))
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
                        with ThreadPoolExecutor(max_workers=1) as executor:
                            future = executor.submit(create_kibana_dashboard, elastic_index, dashboard_path,
                                                     dashboard_id)
                            future.result(10)
                    except Exception as e:
                        logger.error("Error creating Kibana dashboard: %s" % e)
                        dashboard_id = ""
                    query = "INSERT INTO elastic_indexes (username, elastic_index, dashboard_id) VALUES (?, ?, ?)"

                    logger.debug("Executing %s" % query)
                    cur.execute(query, (username, elastic_index, dashboard_id))
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
                        conf += line.replace("test", elastic_index).replace("#", "").replace('target=""',
                                                                                             'target="%s"' % collector_ip).replace(
                            'port=""', 'port="%s"' % logstash_port)

                with open(rsyslog_conf, "w") as fd_new:
                    fd_new.write(conf)

                link = "http://%s:%s/dashboard/%s" % (get_config("system", "ip", config_file_path=config_path),
                                                      get_config("api", "port", config_file_path=config_path),
                                                      random_id)
                logger.debug("Dashboard link: %s" % link)
                # response["log_dashboard_link"] = link
                response["log_dashboard_link"] = "Loading"
                # response.append(json.dumps({"log_dashboard_link": link}))

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

            if resource_id == "suricata" and "rules" in properties:
                """Add rules to signatures.rules file"""
                rules = ""
                for r in properties["rules"]:
                    rules += r + "\n"

                rules_file_path = "%s/scripts/signatures.rules" % tmp_files_path
                with open(rules_file_path, "w") as fd:
                    fd.write(rules)

            tar = tarfile.open(name=tar_filename, mode='w')

            if "want_agent" in properties and properties["want_agent"]:
                '''Prepare .tar with custom scripts'''

                tar.add('%s/scripts' % tmp_files_path, arcname='')
                tar.close()

                link = "http://%s:%s/%s/%s" % (get_config("system", "ip", config_file_path=config_path),
                                               get_config("api", "port", config_file_path=config_path),
                                               properties["resource_id"], random_id)
                logger.debug(link)
                response["download_link"] = link
                # url from dev template
                # response["download_link"] = scripts_url = "%s/%s.tar" % (self.get_config_value("remote-files", "url"), properties["resource_id"])

                update = False
                disable_port_security = False
            else:
                # testbed = properties["testbed"]
                vnfd = {}
                with open("%s/vnfd.json" % tmp_files_path, "r") as fd:
                    vnfd = json.loads(fd.read())
                print_payload(vnfd, "VNF Descriptor")
                # if problems occur when all VNF have same name so uncomment
                vnfd["name"] += ("-%s" % random_id)
                vnfd["type"] = vnfd["name"]

                vnfd["vdu"][0]["vimInstanceName"] = ["vim-instance-%s" % testbed]

                '''

                vnfd["vdu"][0]["vm_image"][0] = properties["os_image_name"]

                '''
                if "lan_name" in properties:
                    vnfd["vdu"][0]["vnfc"][0]["connection_point"][0]["virtual_link_reference"] = properties["lan_name"]
                    vnfd["virtual_link"][0]["name"] = properties["lan_name"]

                body = {}

                # if "ssh_pub_key"
                if "ssh_key" in properties:
                    key_name = "securityResourceKey"
                    open_baton.import_key(properties["ssh_key"], key_name)
                    body = {"keys": [key_name]}

                with open("%s/vnfd.json" % tmp_files_path, "w") as fd:
                    fd.write(json.dumps(vnfd))

                # if problems occur when all VNF have same name so uncomment
                with open("%s/Metadata.yaml" % tmp_files_path, "r") as f:
                    #    #meta_yaml = json.loads(f.read())
                    meta_yaml = yaml.load(f)

                with open("%s/Metadata.yaml" % tmp_files_path, "w") as f:
                    meta_yaml["name"] += ("-%s" % random_id)
                    #    #f.write(json.dumps(meta_yaml))
                    yaml.dump(meta_yaml, f)

                '''Prepare VNFPackage'''
                tar.add('%s' % tmp_files_path, arcname='')
                tar.close()
                nsr_details = {}
                logger.debug("Open Baton project_id: %s" % ob_project_id)
                try:
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(open_baton.deploy_package, tar_filename, body, resource_id)
                        return_val = future.result(60)

                    nsr_details = json.loads(return_val)
                    nsr_id = nsr_details["id"]
                    nsd_id = nsr_details["descriptor_reference"]
                    response["NSR Details"] = {"status": nsr_details["status"], 'nsr_id': nsr_id}
                    update = True
                    disable_port_security = True

                except Exception as e:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    traceback.print_tb(exc_traceback)
                    msg = e.message or e.args
                    message = "Error deploying the Package on Open Baton: %s" % msg
                    logger.error(message)
                    nsr_id = "ERROR"
                    update = False
                    disable_port_security = False
                    response["NSR Details"] = "ERROR: %s" % message

        elif resource_id == "pfsense":

            response = {}
            response['random_id'] = random_id

            openstack = OSclient(testbed, username, os_project_id)
            ob_project_id = user_info.ob_project_id
            open_baton = OBClient(ob_project_id)

            try:
                ret = openstack.deploy_pfSense({"wan": properties["wan_name"], "lan": properties["lan_name"]})
                logger.debug(ret)

                pfsense_ip = ret["ip"]
                os_instance_id = ret["id"]
                lan_ip = ret['lan_ip']
                floating_ip = ret['ip']
                disable_port_security = True
                update = True
                logger.debug("ip: %s, len %d" % (lan_ip, len(lan_ip)))

                # Deploy bridge VM as pfsense slave
                logger.info("Starting deploing bridge VM")
                scripts_url = "%s/bridge.tar" % self.get_config_value("remote-files", "url")
                tar_filename = "%s/bridge.tar" % tmp_files_path

                logger.debug("getting tar from %s to %s" % (scripts_url, tar_filename))
                r = requests.get(scripts_url, stream=True)
                with open(tar_filename, 'wb') as fd:
                    for chunk in r.iter_content(chunk_size=128):
                        fd.write(chunk)

                tar = tarfile.open(name=tar_filename, mode="r")
                tar.extractall(path=tmp_files_path)
                tar.close()

                with open("%s/vnfd.json" % tmp_files_path, "r") as fd:
                    vnfd = json.loads(fd.read())

                vnfd["vdu"][0]["vimInstanceName"][0] = vnfd["vdu"][0]["vimInstanceName"][0].format(testbed)
                logger.debug("vnfd testbed: %s" % vnfd["vdu"][0]["vimInstanceName"])

                vnfd["vdu"][0]["vnfc"][0]["connection_point"][0]["virtual_link_reference"] = properties["lan_name"]
                vnfd["virtual_link"][0]["name"] = properties["lan_name"]
                logger.debug("virtual_link: %s, vdu connection_point: %s" % (
                    vnfd["vdu"][0]["vnfc"][0]["connection_point"][0]["virtual_link_reference"], \
                    vnfd["virtual_link"][0]["name"]))

                logger.info("packing VNFD")
                with open("%s/vnfd.json" % tmp_files_path, "w") as fd:
                    fd.write(json.dumps(vnfd))
                tar = tarfile.open(name=tar_filename, mode='w')
                tar.add('%s' % tmp_files_path, arcname='')
                tar.close()

                logger.debug("Open Baton project_id: %s" % ob_project_id)
                try:
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(open_baton.deploy_package, tar_filename, {}, "bridge")
                        return_val = future.result(60)

                    nsr_details = json.loads(return_val)
                    logger.debug(nsr_details)

                    # saving bridge info to db to later update phase
                    conn = sqlite3.connect(self.resources_db)
                    cur = conn.cursor()
                    # TODO remove OB id after deploying bridge from OS
                    query = "INSERT INTO resources (username, resource_id, ob_project_id, ob_nsr_id, ob_nsd_id, testbed, random_id, os_project_id, os_instance_id, to_update) \
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

                    logger.info("Saving project to db. user=%s, resource_id=%s" % (username, resource_id))
                    logger.debug("Executing %s" % query)
                    logger.debug("value = {%s, %s, %s, %s, %s, %s, %s, %s, %s, %s}" % (
                        username, "bridge", ob_project_id, nsr_details["id"], nsr_details["descriptor_reference"],
                        testbed,
                        random_id, os_project_id, "NONE", True))

                    cur.execute(query, (
                        username, "bridge", ob_project_id, nsr_details["id"], nsr_details["descriptor_reference"],
                        testbed,
                        random_id, os_project_id, "NONE", True))
                    conn.commit()
                    conn.close()

                    response["status"] = "loading"

                except Exception as e:
                    # TODO
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    traceback.print_tb(exc_traceback)
                    msg = e.message or e.args
                    message = "Error deploying the Package on Open Baton: %s" % msg
                    logger.error(message)
                    nsr_id = "ERROR"
                    update = False
                    disable_port_security = False
                    response["NSR Details"] = "ERROR: %s" % message


            except Exception as e:
                logger.error(e)
                response["ip"] = "Error deploying pfSense"
                return [json.dumps(response)]

        conn = sqlite3.connect(self.resources_db)
        cur = conn.cursor()
        query = "INSERT INTO resources (username, resource_id, testbed, ob_project_id, ob_nsr_id, ob_nsd_id, random_id, os_project_id, os_instance_id, to_update, disable_port_security, lan_ip, floating_ip) \
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

        logger.info("Saving project to db. user=%s, resource_id=%s" % (username, resource_id))
        logger.debug("Executing %s" % query)
        logger.debug("lan_ip obj type: %s" % type(lan_ip))
        logger.debug("value = {%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s}" % (
            username, resource_id, testbed, ob_project_id, nsr_id, nsd_id, random_id, os_project_id, os_instance_id,
            update,
            disable_port_security, lan_ip))

        cur.execute(query, (
            username, resource_id, testbed, ob_project_id, nsr_id, nsd_id, random_id, os_project_id, os_instance_id,
            update,
            disable_port_security, lan_ip, floating_ip))
        conn.commit()
        conn.close()

        '''
        Return an array of JSON strings with information about the resources
        '''
        logger.debug("Responding %s" % json.dumps(response))
        return [json.dumps(response)]
        # return [json.dumps({"status": "NULL"})]

    def configure_ELK(self, username, random_id):
        '''Repush index-pattern'''
        logger.debug("Checking if resource has requested elastic index")
        conn_elastic = sqlite3.connect(self.resources_db)
        conn_elastic.row_factory = sqlite3.Row
        cur = conn_elastic.cursor()
        query = "SELECT e.elastic_index FROM resources AS r JOIN elastic_indexes AS e ON r.username = e.username WHERE e.username=?"  # WHERE r.to_update='True'"
        res = cur.execute(query, (username,))
        elastic_index = res.fetchone()
        conn_elastic.close()

        if elastic_index:
            index = elastic_index["elastic_index"]
            logger.info("Creating Elasticsearch index")
            link = "http://%s:%s/dashboard/%s" % (get_config("system", "ip", config_file_path=config_path),
                                                  get_config("api", "port", config_file_path=config_path),
                                                  random_id)
            logger.debug("Eleastic dashboard link: %s" % link)
            try:
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(push_kibana_index, index)
                    future.result(5)
            except Exception as e:
                logger.error("Problem contacting the log collector: %s" % e)
                link = "ERROR: %e" % e
            return link
        return None

    def _update_pfsense(self, testbed, os_project_id, username, random_id, resource_id):
        result = {}
        try:
            logger.info("Disabling port security on VM")
            logger.debug("connecting to openstak. testbed=%s, project=%s" % (testbed, os_project_id))
            openstack = OSclient(testbed, "", os_project_id)

            for srv in openstack.list_server(os_project_id):
                if re.search("pfsense", srv.name) and srv.tenant_id == os_project_id:
                    openstack.allow_forwarding(srv.id)
                    disable_port_security = False
                    to_update = False
                    query = "UPDATE resources SET disable_port_security = ?, to_update = ?  WHERE username = ? AND random_id = ? AND resource_id = ?"
                    execute_query(self.resources_db, query,
                                  (disable_port_security, to_update, username, random_id, resource_id))
        except Exception as e:
            logger.error("Error disabling port security: {0}".format(e))
            result["status"] = "ERROR disabling port security"

        return result

    def _update_bridge(self, ob_project_id, nsr_id, username, random_id, ob_nsd_id):
        result = {}

        open_baton = OBClient(ob_project_id)
        agent = open_baton.agent
        nsr_agent = agent.get_ns_records_agent(project_id=ob_project_id)
        ob_resp = nsr_agent.find(nsr_id)
        time.sleep(5)
        nsr_details = json.loads(ob_resp)

        if len(nsr_details["vnfr"]) > 0 and len(nsr_details["vnfr"][0]["vdu"][0]["vnfc_instance"]) > 0:
            bridge_vdu = nsr_details["vnfr"][0]["vdu"][0]
            floating_ip = bridge_vdu["vnfc_instance"][0]["floatingIps"][0]["ip"]
            logger.info("bridge floating ip: %s" % floating_ip)
            conn = sqlite3.connect(self.resources_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            query = "SELECT lan_ip, floating_ip FROM resources WHERE resource_id='pfsense' AND username=?"
            pfsense_res = cur.execute(query, [username]).fetchone()
            conn.close()
            pfsense_lan_ip = pfsense_res['lan_ip']
            pfsense_floating_ip = pfsense_res['floating_ip']
            logger.debug(pfsense_lan_ip)
            try:
                tmp_files_path = "%s/tmp/%s" % (self.local_files_path, random_id)
                pfsense_scripts_url = "%s/pfsense_utils.py" % re.sub("/etc/resources", "/eu/softfire/sec/utils",
                                                                     self.get_config_value("remote-files", "url"))
                script_filename = "%s/pfsenes_utils.py" % tmp_files_path

                r_script = requests.get(pfsense_scripts_url, stream=True)
                with open(script_filename, 'wb') as fd:
                    for chunk in r_script.iter_content(chunk_size=128):
                        fd.write(chunk)

                exit_status = os.system("python %s %s %s" % (script_filename, floating_ip, pfsense_lan_ip))
                logger.debug("exit status %d" % exit_status)
                if exit_status != 0:
                    result["status"] = "Loading"
                else:
                    try:
                        open_baton = OBClient(ob_project_id)
                        open_baton.delete_ns(nsr_id=nsr_id, nsd_id=ob_nsd_id)

                        query = "DELETE FROM resources WHERE username = ? AND resource_id = ?"
                        logger.debug("executing query")
                        execute_query(self.resources_db, query, (username, "bridge"))

                        result["floating ip"] = [pfsense_floating_ip,
                                                 {"VM credentials": {"username": "root", "password": "pfsense"}}]
                        result["lan ip"] = pfsense_lan_ip
                        result["dashboard credentials"] = {"username": "admin", "password": "pfsense"}
                    except Exception as e:
                        logger.error("Problem contacting Open Baton: {}".format(e))
                        result["status"] = "ERROR: OB error"
            except Exception as e:
                logger.error(e)
                result["status"] = "ERROR deploying pfense: network error"
        else:
            logger.info("bridge not ready")
            result["status"] = "Loading"
        logger.debug(result)
        return result

    def _update_ob_resources(self, ob_project_id, nsr_id, username, os_project_id, testbed, disable_port_security,
                             resource_id, random_id):
        result = {}

        try:
            open_baton = OBClient(ob_project_id)
            agent = open_baton.agent
            nsr_agent = agent.get_ns_records_agent(project_id=ob_project_id)
            ob_resp = nsr_agent.find(nsr_id)
            time.sleep(5)
            nsr_details = json.loads(ob_resp)
            result["status"] = nsr_details["status"]

            """Disable port security on VM's ports"""
            if disable_port_security == True:
                try:
                    logger.info("Disabling port security on VM")

                    logger.debug("connecting to openstak. testbed=%s, project=%s" % (testbed, os_project_id))
                    openstack = OSclient(testbed, "", os_project_id)

                    for vnfr in nsr_details["vnfr"]:
                        for vdu in vnfr["vdu"]:
                            for vnfc_instance in vdu["vnfc_instance"]:
                                server_id = vnfc_instance["vc_id"]
                                logger.debug("disable port security on VM with UUID: %s" % server_id)
                                openstack.allow_forwarding(server_id)
                                disable_port_security = "False"
                    query = "UPDATE resources SET disable_port_security = ? WHERE username = ? AND ob_nsr_id = ?"
                    execute_query(self.resources_db, query, (disable_port_security, username, nsr_id))
                except Exception as e:
                    logger.error("Error disabling port security: {0}".format(e))
                    result["status"] = "ERROR: problem disabling port security"

        except Exception as e:
            logger.error("Error contacting Open Baton to check resource status, nsr_id: %s\n%s" % (nsr_id, e))
            result["status"] = "ERROR checking status"

        if result["status"] == "ACTIVE":
            result["ip"] = nsr_details["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]["ip"]
            if resource_id == "firewall":
                try:
                    api_url = "http://%s:5000" % result["ip"]
                    api_resp = requests.get(api_url)
                    logger.debug(api_resp)
                    result["api_url"] = api_url
                except Exception as e:
                    logger.error(e)
                    result["status"] = "VM is running but API are unavailable"

            dashboard_l = self.configure_ELK(username, random_id)
            if dashboard_l:
                result["dashboard_log_link"] = dashboard_l

            try:
                """Update DB entry to stop sending update"""
                query = "UPDATE resources SET to_update='False' WHERE ob_nsr_id=? AND username=?"
                execute_query(self.resources_db, query, (nsr_id, username))
            except Exception:
                logger.error("Error updating resource row into DB. attr to_update")

        if re.match("ERROR", result["status"]):
            try:
                query = "UPDATE resources SET to_update='False' WHERE ob_nsr_id=? AND username=?"
                execute_query(self.resources_db, query, (nsr_id, username))
            except Exception as e:
                logger.error(e)

        result["NSR Details"] = {"status": nsr_details.get('status'), 'nsr_id': nsr_details.get('id')}

        return result

    def _update_status(self) -> dict:
        response = {}

        try:
            conn = sqlite3.connect(self.resources_db)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            query = "SELECT * FROM resources WHERE to_update=1"
            res = cur.execute(query)
            rows = res.fetchall()
            if len(rows) > 0:
                logger.debug("resource to check: %d" % len(rows))
        except Exception as e:
            logger.error("Problem reading the Resources DB: %s" % e)
            conn.close()
            # FIXME this return
            response["ERROR"] = "Security Manager engine error"
            return response

        for r in rows:
            logger.debug("Now checking %s ob_id:%s" % (r["resource_id"], r["ob_project_id"]))
            resource_response = {}
            '''nsr_id and ob_project_id could be empty with want_agent'''
            nsr_id = r["ob_nsr_id"]
            resource_id = r["resource_id"]
            ob_project_id = r["ob_project_id"]
            testbed = r["testbed"]
            os_project_id = r["os_project_id"]
            os_instance_id = r["os_instance_id"]
            disable_port_security = r["disable_port_security"]
            username = r["username"]
            random_id = r["random_id"]
            resource_id = r["resource_id"]

            if r["to_update"] == True:

                '''Open Baton resource'''
                logger.debug("Getting status nsr_id: %s" % nsr_id)

                if resource_id == "pfsense":
                    resource_response = self._update_pfsense(testbed, os_project_id, username, random_id, resource_id)

                if resource_id == "bridge":
                    resource_response = self._update_bridge(ob_project_id, nsr_id, username, random_id, r["ob_nsd_id"])

                if resource_id == "suricata" or resource_id == "firewall":
                    resource_response = self._update_ob_resources(ob_project_id, nsr_id, username, os_project_id,
                                                                  testbed, disable_port_security, resource_id,
                                                                  random_id)

                resource_response['random_id'] = random_id

            else:
                resource_response = {}

            if len(resource_response):
                if username not in response.keys():
                    response[username] = []
                logger.debug("Result: %s" % resource_response)
                response[username].append(json.dumps(resource_response))
        return response

    def release_resources(self, user_info=None, payload=None):
        username = user_info.name

        logger.info("Requested release_resources by user %s" % username)
        logger.debug("Arrived release_resources. Payload: %s" % payload)

        conn = sqlite3.connect(self.resources_db)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        query = "SELECT * FROM resources WHERE username = ?"
        res = cur.execute(query, (username,))
        rows = res.fetchall()
        logger.debug(rows)
        for r in rows:
            if r["ob_nsr_id"] != "" and r["ob_nsr_id"] != "ERROR":
                try:
                    open_baton = OBClient(r["ob_project_id"])
                    open_baton.delete_ns(nsr_id=r["ob_nsr_id"], nsd_id=r["ob_nsd_id"])
                except Exception as e:
                    logger.error("Problem contacting Open Baton: {}".format(e))

                    #            if r["os_instance_id"] != "" :
            if r["resource_id"] == "pfsense":
                try:
                    logger.debug("Deleting resource with id: {0}".format(r["os_instance_id"]))
                    openstack = OSclient(r["testbed"], username, r["os_project_id"])
                    openstack.delete_server(r["os_instance_id"])
                except Exception as e:
                    logger.error("Problem contacting OpenStack: {0}".format(e))
            file_path = "%s/tmp/%s" % (self.local_files_path, r["random_id"])
            try:
                shutil.rmtree(file_path)
            except FileNotFoundError:
                logger.error("FileNotFoud: %s" % file_path)

        query = "DELETE FROM resources WHERE username = ?"
        cur.execute(query, (username,))

        query = "DELETE FROM elastic_indexes WHERE username = ?"
        cur.execute(query, (username,))

        conn.commit()
        conn.close()

        return


if __name__ == "__main__":
    from eu.softfire.sec.utils.utils import config_path
    import os


    # This is a test-case UserInfo to test the component whitout the Experiment Manager
    class UserInfo:
        def __init__(self, username, password, os_project_id, ob_project_id):
            self.name = username
            self.password = password
            self.os_project_id = os_project_id
            self.ob_project_id = ob_project_id


    os.environ["http_proxy"] = ""
    # Fokus
    user = UserInfo("", "", "2927f3e448ef49f782e13af735036756", "ee06166e-d6e2-4743-8edc-c33e1e76899e")
    # Fokus-dev
    #    user = UserInfo("softfire", "hRvB2u8K", "5ff22e03cfb94ed6b8194aa5532444be", "12bff78c-71a3-4b27-81cc-bba3d48c1a72")
    # Surrey
    #    user = UserInfo("softfire", "hRvB2u8K", "bce66fc15ad94db2b291bfe12c8b0f8f", "12bff78c-71a3-4b27-81cc-bba3d48c1a72")
    # ADS
    #    user = UserInfo("softfire", "hRvB2u8K", "9dfc795ab5bb4bd89ca85969fcc93bfd", "12bff78c-71a3-4b27-81cc-bba3d48c1a72")

    pfsense_resource = """properties:
        resource_id: pfsense
        testbed: fokus
        wan_name: softfire-network_new
        lan_name: softfire-internal-new
        """
    fw_resource = """properties:
        resource_id: firewall
        want_agent: false
        lan_name: softfire-internal
        testbed: fokus
        default_rule: allow
        denied_ips: [172.20.10.138]
        logging: false
        ssh_key: ""
    """
    suricata_resource = """properties:
        resource_id: suricata
        want_agent: False
        lan_name: softfire-internal
        testbed: fokus
        ssh_key: ""
        rules: 
            - alert icmp any any -> $HOME_NET any (msg:”ICMP test”; sid:1000001; rev:1; classtype:icmp-event;)
        logging: False
    """

    resource = fw_resource
    sec = SecurityManager(config_path)
    # sec.validate_resources(user, payload=resource)
    # sec.provide_resources(user, payload=resource)
    input("hit enter to update...")
    while True:
        sec._update_status()
        input("hit enter to release")
        break
    sec.release_resources(user)
