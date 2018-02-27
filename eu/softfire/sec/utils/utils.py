import json
import logging.config
import random
import requests
import string
import time
from threading import Thread
import sqlite3

from sdk.softfire.utils import *

config_path = '/etc/softfire/security-manager.ini'

def get_logger(config_path, name):
    logging.config.fileConfig(config_path)
    l = logging.getLogger(name)
    return l
logger = get_logger(config_path, __name__)

def random_string(size):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(size))

def add_rule_to_fw(fd, rule):
    fd.write("curl -X POST -H \"Content-Type: text/plain\" -d '%s' http://localhost:5000/ufw/rules\n" % rule)


def get_kibana_element(el_type, el_id):
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    resp = requests.get("http://%s:%s/.kibana/%s/%s" % (elastic_ip, elastic_port, el_type, el_id))
    logger.debug("Kibana element type=%s, GET: %s" % (el_type, resp))
    return resp.json()


def post_kibana_element(el_type, el_id, data):
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    resp = requests.post("http://%s:%s/.kibana/%s/%s" % (elastic_ip, elastic_port, el_type, el_id), data=data)
    logger.debug("elem type=%s, id=%s" % (el_type, el_id))
    print(data)
    return resp.json()


def push_kibana_index(elastic_index):
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    r_check = requests.get("http://%s:%s/.kibana/index-pattern/%s-*" % (elastic_ip, elastic_port, elastic_index)).json()
    if r_check["found"]:
        return
    '''Push of the Index pattern to Elasticsearch'''
    url = "http://%s:%s/.kibana/index-pattern/%s-*" % (elastic_ip, elastic_port, elastic_index)
    r = requests.get("http://%s:%s/.kibana/index-pattern/%s-*" % (elastic_ip, elastic_port, "logstash")).json()
    data = {"title": "%s-*" % elastic_index, "timeFieldName": "@timestamp", "fields": r["_source"]["fields"]}
    #logger.debug("Pushing %s to %s" % (data, url))
    resp = requests.post(url, data=json.dumps(data))
    logger.debug("kibana index POST: %s" % resp)


def create_kibana_dashboard(elastic_index, dashboard_path, dashboard_id):
    logger.debug("Start creating dashboard")
    collector_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)
    dashboard_template = get_config("log-collector", "dashboard-template", config_path)
    kibana_port = get_config("log-collector", "kibana-port", config_path)

    logger.debug("ip=%s, e=%s, k=%s"  % (collector_ip, elastic_port, kibana_port))
    logger.debug("template=%s" % dashboard_template)

    '''Push of the Index pattern to Elasticsearch'''
    push_kibana_index(elastic_index)

    logger.debug("Dashboard -----------------------:")
    dashboard = get_kibana_element("dashboard", dashboard_template)
    panels = json.loads(dashboard["_source"]["panelsJSON"])

    '''Cycle through the dashboards panel to see which need to be changed'''
    for i, p in enumerate(panels):

        '''Get the element'''
        logger.debug("Getting element %s" %p["id"])
        element = get_kibana_element(p["type"], p["id"])
        source = json.loads(element["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"])

        '''If the element contain the index, this need to be changed'''
        if "index" in source.keys():
            source["index"] = "%s-*" % elastic_index
            logger.debug("New index %s" %source["index"])
            element["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(source)
            el_id = random_string(15)
            r = post_kibana_element(p["type"], el_id, json.dumps(element["_source"]))

            logger.debug("element POST: %s" % r)
            '''Attach new id of the element'''
            panels[i]["id"] = el_id
        else:
            logger.debug("elem with no index")

    dashboard["_source"]["panelsJSON"] = json.dumps(panels)

    '''Push new dashboard'''
    r = post_kibana_element("dashboard", dashboard_id, json.dumps(dashboard["_source"]))
    logger.debug("dashboard final POST: %s" % r)
    store_kibana_dashboard(dashboard_path, collector_ip, kibana_port, dashboard_id)
    return


def store_kibana_dashboard(dashboard_path, collector_ip, kibana_port, dashboard_id):
    '''Store dashboard webpage'''

    with open(dashboard_path, "w") as dfd:
        html = '''<iframe src="http://{0}:{1}/app/kibana#/dashboard/{2}?embed=true&_g=()" height=1000\% width=100\%></iframe>'''.format(
            collector_ip, kibana_port, dashboard_id)
        dfd.write(html)

def execute_query(db, query, args):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    conn.close()

