from toscaparser.tosca_template import ToscaTemplate as ToscaTemplate
import yaml
from org.openbaton.cli.agents.agents import OpenBatonAgentFactory
from sdk.softfire.utils import *


def deploy_openbaton_nsr(project_id="761d8b56-b21a-4db2-b4d2-16b05a01bc7e", nsd_id="50361f5e-ff36-4874-b8c1-d3552b8beb80", testbed=None) :
    #TODO from conf
    conf = get_config_parser("etc/security-manager.ini")
    ob_conf = conf["open-baton"]
    agent = OpenBatonAgentFactory(nfvo_ip=ob_conf["ip"], nfvo_port=int(ob_conf["port"]), https=(ob_conf["https"] == "True"), version=int(ob_conf["version"]), username=ob_conf["username"], password=ob_conf["password"], project_id=project_id)
    nsr_ag = agent.get_ns_records_agent(project_id=project_id)
    nsr_ag.create(entity=nsd_id)

def deploy_firewall_resource(node_properties) :
    #TODO Check for missing/conflicting values
    want_agent = bool(node_properties["want_agent"].value)
    default_rule = node_properties["default_rule"].value
    #testbed = node_properties["testbed"].value
    logging = node_properties["logging"].value
    #allowed_ips = node_properties["allowed_ips"].value
    denied_ips = node_properties["denied_ips"].value

    #TODO Adapt configuration with specified walues
    print(denied_ips)
    '''
    - Option 1: modify the package and then upload it on Open Baton. Valid for both want_agent or not
    - Option 2: Configure via APIs
    '''

    if want_agent :
        pass
    else :
        #TODO
        ''' Deploy the firewall by means of Open Baton '''
        pass

    #TODO Store active resources for every experiment.
    return None


print(get_config(section="messaging", key="bind_port", config_file_path="etc/security-manager.ini"))
c = get_config_parser("etc/security-manager.ini")
print(c["open-baton"]["ip"])
deploy_openbaton_nsr()


'''
Parse TOSCA template looking for nodes SecurityResource, and create a list
'''
security_nodes = []
#TODO testing from file. To get from experiment manager
with open("tosca-ex.yaml", 'r') as stream:
    try:
        # Probabilmente posso/devo scegliere un altro modo
        tpl = ToscaTemplate(yaml_dict_tpl = yaml.load(stream))
    except Exception as e : #TODO
        print(e)
    for node in tpl.nodetemplates:
        #logger.debug("Found node: %s of type %s with properties: %s" % (
        #            node.name, node.type, list(node.get_properties().keys())))
        print("Found node: %s of type %s with properties: %s" % (node.name, node.type, list(node.get_properties().keys())))
        if node.type == "SecurityResource" :
            security_nodes.append(node)

#TODO Check status of resources that the security-manager thinks to be active

for node in security_nodes :
    node_properties = node.get_properties()

    if node_properties["resource_id"].value == "firewall" :
        ''' The requested resource is a firewall '''
        deploy_firewall_resource(node_properties)
    else :
        ''' ERROR: Unexisting SecurityResource '''
        #TODO
        pass




