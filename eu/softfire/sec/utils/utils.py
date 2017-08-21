import json
import logging.config
import random
import requests
import string
import time
from threading import Thread
import sqlite3

from keystoneauth1 import identity, session, loading

from org.openbaton.cli.agents.agents import OpenBatonAgentFactory
from sdk.softfire.utils import *

config_path = '/etc/softfire/security-manager.ini'


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
                    logger = get_logger(config_path, __name__)
                    print("got error while updating resources: %s " % e)
                    logger.error("got error while updating resources: %s " % e)
                    self.manager.send_update()

    def stop(self):
        self.stopped = True


def get_logger(config_path, name):
    logging.config.fileConfig(config_path)
    return logging.getLogger(name)


def random_string(size):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))


def deploy_package(path, project_id):
    '''Open Baton Login'''
    agent = ob_login(project_id)

    '''Upload the VNFP'''
    vnfp_agent = agent.get_vnf_package_agent(project_id=project_id)
    vnfp = vnfp_agent.create(path)

    '''Create and upload the NSD'''
    #nsd_file_path = "etc/resources/nsd-fw.json"

    remote_url = get_config("remote-files", "url", config_path)
    r = requests.get("%s/nsd-fw.json" % remote_url)
    nsd = json.loads(r.text)

    nsd_agent = agent.get_ns_descriptor_agent(project_id)
    '''
    nsd = {}
    with open(nsd_file_path, "r") as fd:
        nsd = json.load(fd)
    '''
    nsd["vnfd"] = [{"id": vnfp["id"]}]
    print(nsd)
    nsd = nsd_agent.create(json.dumps(nsd))

    '''Deploy of the NSR'''
    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
    nsr = nsr_agent.create(entity=nsd["id"])

    nsr_details = nsr_agent.find(nsr["id"])

    '''Assuming 1 VNFR, 1 VDU, 1 VNC_Instance, 1 Floating IP'''
    # floating_ip = nsr_details["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]
    floating_ip = "test"
    return nsr_details


def delete_ns(nsr_id, nsd_id, project_id):
    agent = ob_login(project_id)
    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
    nsr_agent.delete(nsr_id)

    nsd_agent = agent.get_ns_descriptor_agent(project_id)
    time.sleep(5)  # Give Open Baton time to process the request
    nsd_agent.delete(nsd_id)


def ob_login(project_id):
    ob_conf = get_config_parser(config_path)["open-baton"]

    '''Open Baton Login'''
    agent = OpenBatonAgentFactory(nfvo_ip=ob_conf["ip"], nfvo_port=int(ob_conf["port"]),
                                  https=(ob_conf["https"] == "True"), version=int(ob_conf["version"]),
                                  username=ob_conf["username"], password=ob_conf["password"], project_id=project_id)
    return agent


def add_rule_to_fw(fd, rule):
    fd.write("curl -X POST -H \"Content-Type: text/plain\" -d '%s' http://localhost:5000/ufw/rules\n" % rule)


def get_kibana_element(el_type, el_id):
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    resp = requests.get("http://%s:%s/.kibana/%s/%s" % (elastic_ip, elastic_port, el_type, el_id))
    print(resp)
    return resp.json()


def post_kibana_element(el_type, el_id, data):
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    resp = requests.post("http://%s:%s/.kibana/%s/%s" % (elastic_ip, elastic_port, el_type, el_id), data=data)
    return resp.json()


def push_kibana_index(elastic_index):
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    '''Push of the Index pattern to Elasticsearch'''
    url = "http://%s:%s/.kibana/index-pattern/%s-*" % (elastic_ip, elastic_port, elastic_index)
    data = {"title": "%s-*" % elastic_index, "timeFieldName": "@timestamp"}
    print("Pushing %s to %s" % (data, url))
    resp = requests.post(url, data=json.dumps(data))
    print(resp)


def create_kibana_dashboard(elastic_index, dashboard_path, dashboard_id):
    logger = get_logger(config_path, __name__)

    logger.debug("Start creating dashboard")
    collector_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    dashboard_template = get_config("log-collector", "dashboard-template", config_path)
    kibana_port = get_config("log-collector", "kibana-port", config_path)

    '''Push of the Index pattern to Elasticsearch'''
    push_kibana_index(elastic_index)

    dashboard = get_kibana_element("dashboard", dashboard_template)
    panels = json.loads(dashboard["_source"]["panelsJSON"])

    '''Cycle through the dashboards panel to see which need to be changed'''
    for i, p in enumerate(panels):

        '''Get the element'''
        element = get_kibana_element(p["type"], p["id"])
        source = json.loads(element["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"])

        '''If the element contain the index, this need to be changed'''
        if "index" in source.keys():
            source["index"] = "%s-*" % elastic_index
            element["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(source)
            el_id = random_string(15)
            r = post_kibana_element(p["type"], el_id, json.dumps(element["_source"]))

            '''Attach new id of the element'''
            panels[i]["id"] = el_id

    dashboard["_source"]["panelsJSON"] = json.dumps(panels)

    '''Push new dashboard'''
    r = post_kibana_element("dashboard", dashboard_id, json.dumps(dashboard["_source"]))
    print(r)
    store_kibana_dashboard(dashboard_path, collector_ip, kibana_port, dashboard_id)
    return


def store_kibana_dashboard(dashboard_path, collector_ip, kibana_port, dashboard_id):
    '''Store dashboard webpage'''

    with open(dashboard_path, "w") as dfd:
        html = '''<iframe src="http://{0}:{1}/app/kibana#/dashboard/{2}?embed=true&_g=()" height=1000\% width=100\%></iframe>'''.format(
            collector_ip, kibana_port, dashboard_id)
        dfd.write(html)

def execute_query(db, query):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query)
    conn.commit()
    conn.close()

def openstack_login(testbed, project_id, project_name = None):
    #TODO load from file
    openstack_credentials = {
        "ads": {
            "username": "softfire",
            "password": "DrupetruC",
            "auth_url": "http://172.20.70.130:5000/v3",
            "ext_net_name": "public",
            "admin_tenant_name": "softfire",
            "allocate-fip": 0,
            "api_version": 3,
            "admin_project_id": "1e3a8a39d14f47efa0a21b1bcb05fff2",
            "user_domain_name": "default"
        },
        "fokus-dev": {
            "username": "admin",
            "password": "opensdncore",
            "auth_url": "http://172.20.30.5:5000/identity/v3",
            "ext_net_name": "public",
            "admin_tenant_name": "admin",
            "allocate-fip": 0,
            "api_version": 3,
            "admin_project_id": "90fac20daa5d41799804978d9925bb97",
            "user_domain_name": "default"
        },
        "fokus": {
            "username": "softfire-openbaton",
            "password": "awbijAk3Slat",
            "auth_url": "http://172.20.30.3:5000/v3",
            "ext_net_name": "softfire-network",
            "admin_tenant_name": "5gcore",
            "allocate-fip": 0,
            "api_version": 3,
            "admin_project_id": "0bd6efde713446fb92251c5fab2c8384",
            "user_domain_name": "default"
        },
        "ericsson": {
            "username": "admin",
            "password": "8xCYSLx7",
            "auth_url": "http://sfctrl1.rmedlab.eld.it.eu.ericsson.se:5000/v3/",
            "ext_net_name": "softfire-external",
            "admin_tenant_name": "admin",
            "allocate-fip": 0,
            "api_version": 3,
            "admin_project_id": "fed0b52c7e034d5785880613e78d4411",
            "user_domain_name": "Default"
        },
        "surrey": {
            "username": "admin",
            "password": "d98b05684dfc4df6",
            "auth_url": "http://10.5.22.25:5000/v3",
            "ext_net_name": "softfire-external",
            "admin_tenant_name": "admin",
            "allocate-fip": 0,
            "api_version": 3,
            "admin_project_id": "4a2931890f734144968d9097f175f7c7",
            "user_domain_name": "Default"
        },
        "reply": {
            "username": "admin",
            "password": "password",
            "auth_url": "http://10.20.70.2:5000/v3",
            "ext_net_name": "public",
            "admin_tenant_name": "security-chain-test",
            "allocate-fip": 0,
            "api_version": 3,
            "admin_project_id": "4a2931890f734144968d9097f175f7c7",
            "user_domain_name": "Default"
        }

    }

    admin_username = openstack_credentials[testbed]["username"]
    password =  openstack_credentials[testbed]["password"]
    auth_url = openstack_credentials[testbed]["auth_url"]
    user_and_project_domain_name  = openstack_credentials[testbed]["user_domain_name"]

    if openstack_credentials[testbed]["api_version"] == 2:
    #    print("{}connecting to {} using v2 auth".format(log_header, auth_url))
        OSloader = loading.get_plugin_loader('password')
        auth = OSloader.load_from_options(
            auth_url=auth_url,
            username=admin_username,
            password=password,
            # tenant_name=self.openstack_credentials[self.usersData[username]["testbed"]]["admin_tenant_name"],
            tenant_name=project_name,
        )

    if openstack_credentials[testbed]["api_version"] == 3:
    #    print("{}connecting to {} using v3 auth".format(log_header, auth_url))

        auth = identity.v3.Password(
            auth_url=auth_url,
            username=admin_username,
            password=password,
            project_domain_name=user_and_project_domain_name,
            user_domain_name=user_and_project_domain_name,
            # project_id=self.openstack_credentials[self.usersData[username]["testbed"]]["project_id"],
            project_id=project_id
        )

    os_session = session.Session(auth=auth)

    return os_session

