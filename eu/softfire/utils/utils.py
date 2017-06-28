import logging.config
import random, string, json, time, requests
from threading import Thread
from org.openbaton.cli.agents.agents import OpenBatonAgentFactory
from sdk.softfire.utils import *

config_path = '/etc/softfire/security-manager/security-manager.ini'

class UpdateStatusThread(Thread):
    def __init__(self, manager):
        Thread.__init__(self)
        self.stopped = False
        self.manager = manager

    def run(self):
        while not self.stopped:
            time.sleep(int(self.manager.get_config_value('system', 'update-delay', '10')))
            if not self.stopped:
                #try:
                self.manager.send_update()
                #except Exception as e:
                #    logger.error("got error while updating resources: %s " % e.args)

    def stop(self):
        self.stopped = True

def get_logger(config_path):
    logging.config.fileConfig(config_path)
    return logging.getLogger("security-manager")

def random_string(size):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))

def deploy_package(path, project_id) :

    '''Open Baton Login'''
    agent = ob_login(project_id)

    '''Upload the VNFP'''
    vnfp_agent = agent.get_vnf_package_agent(project_id=project_id)
    vnfp = vnfp_agent.create(path)

    '''Create and upload the NSD'''
    nsd_file_path = "etc/resources/nsd-fw.json"

    nsd_agent = agent.get_ns_descriptor_agent(project_id)
    nsd = {}
    with open(nsd_file_path, "r") as fd:
        nsd = json.load(fd)
    nsd["vnfd"] = [{"id" : vnfp["id"]}]
    print(nsd)
    nsd = nsd_agent.create(json.dumps(nsd))

    '''Deploy of the NSR'''
    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
    nsr = nsr_agent.create(entity=nsd["id"])

    nsr_details = nsr_agent.find(nsr["id"])

    '''Assuming 1 VNFR, 1 VDU, 1 VNC_Instance, 1 Floating IP'''
    #floating_ip = nsr_details["vnfr"][0]["vdu"][0]["vnfc_instance"][0]["floatingIps"][0]
    floating_ip = "test"
    return nsr_details

def delete_ns(nsr_id, nsd_id, project_id) :

    agent = ob_login(project_id)
    nsr_agent = agent.get_ns_records_agent(project_id=project_id)
    nsr_agent.delete(nsr_id)

    nsd_agent = agent.get_ns_descriptor_agent(project_id)
    time.sleep(5) #Give Open Baton time to process the request
    nsd_agent.delete(nsd_id)

def ob_login(project_id):
    ob_conf = get_config_parser(config_path)["open-baton"]

    '''Open Baton Login'''
    agent = OpenBatonAgentFactory(nfvo_ip=ob_conf["ip"], nfvo_port=int(ob_conf["port"]),
                                  https=(ob_conf["https"] == "True"), version=int(ob_conf["version"]),
                                  username=ob_conf["username"], password=ob_conf["password"], project_id=project_id)
    return agent

def add_rule_to_fw(fd, rule) :
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


def create_kibana_dashboard(elastic_index, dashboard_path, dashboard_id) :
    logger = get_logger(config_path)

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
