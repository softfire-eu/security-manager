from eu.softfire.utils.utils import * #, get_kibana_element, post_kibana_element
from sdk.softfire.utils import *
import requests, json

def get_kibana_element(el_type, el_id):
    resp = requests.get("http://%s:%s/.kibana/%s/%s" % (elastic_ip, elastic_port, el_type, el_id))

    #print(repr(resp.json().replace("'{", "{").replace("}'", "}").replace("'[", "[").replace("]'", "]")))
    return resp.json()

def post_kibana_element(el_type, el_id, data):
    resp = requests.post("http://%s:%s/.kibana/%s/%s" % (elastic_ip, elastic_port, el_type, el_id), data=data)
    return resp.json()

def print_json(d):
    print(json.dumps(d,indent=4, separators=(',', ': ')))

if __name__ == "__main__" :
    elastic_ip = get_config("log-collector", "ip", config_path)
    elastic_port = get_config("log-collector", "elasticsearch-port", config_path)

    kibana_port = get_config("log-collector", "kibana-port", config_path)

    #############
    new_index = "new index"
    dashboard = get_kibana_element("dashboard", dashboard_template)
    #############
    panels = json.loads(dashboard["_source"]["panelsJSON"])
    print_json(dashboard)

    '''Cycle through the dashboards panel to see which need to be changed'''
    for i, p in enumerate(panels) :

        '''Get the element'''
        element = get_kibana_element(p["type"], p["id"])
        print(print_json(element))
        source = json.loads(element["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"])

        '''If the element contain the index, this need to be changed'''
        if "index" in source.keys() :
            #TODO Change index
            source["index"] = new_index
            element["_source"]["kibanaSavedObjectMeta"]["searchSourceJSON"] = json.dumps(source)
            el_id = random_string(15)
            r = post_kibana_element(p["type"], el_id, json.dumps(element["_source"]))
            print_json(r)

            '''Attach new id of the element'''
            panels[i]["id"] = el_id

        print("\n\n")
    dashboard["_source"]["panelsJSON"] = json.dumps(panels)
    print_json(dashboard)
    #TODO push new dashboard
    dashboard_id = random_string(15)
    r = post_kibana_element("dashboard", dashboard_id, json.dumps(dashboard["_source"]))
    print_json(r)
    #TODO Store dashboard webpage
    dashboard_page = "prova.html"
    with open(dashboard_page, "w") as dfd :
        print(elastic_ip)
        html = '''<iframe src="http://{0}:{1}/app/kibana#/dashboard/{2}?embed=true&_g=()" height=100\% width=100\%></iframe>'''.format(elastic_ip, kibana_port, dashboard_id)
        print(html)
        dfd.write(html)
    #TODO return link to new dashboard
