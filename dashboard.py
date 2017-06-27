from eu.softfire.utils.utils import * #, get_kibana_element, post_kibana_element
from sdk.softfire.utils import *
import requests, json, time
from eu.softfire import SecurityManager


def print_json(d):
    print(json.dumps(d,indent=4, separators=(',', ': ')))

if __name__ == "__main__" :
    with open("security-resource.yaml", "r") as fd :
        secr = fd.read()

        secman = SecurityManager.SecurityManager("/etc/softfire/security-manager/security-manager.ini")
        secman.release_resources()
        secman.provide_resources(payload=secr, user_info=None)
        for i in range(1,100):

            time.sleep(10)
            secman._update_status()
        secman.release_resources()


