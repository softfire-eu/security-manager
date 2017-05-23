from flask import Flask
from flask import request
#from flask.ext.api import status
import json, httplib, urllib, requests, os, binascii, subprocess
from tinydb import TinyDB, Query

app = Flask(__name__)

db = TinyDB("rules_db.json")
Rule = Query()

id = 0  #TODO in better way


@app.route('/ufw/status', methods=['GET'])
def get_status():
    #TODO To better define the response
    return ufw_command("status")

@app.route('/ufw/rules', methods=["GET", "POST"])
def rules():
    if request.method == "GET" :
        return get_rules_from_db()

    elif request.method == "POST":
        r = request.data.strip()
        try :
            ufw_resp = ufw_command(r)
            print(ufw_resp)
        except subprocess.CalledProcessError :
            return "Syntax error", 400

        if not ufw_resp.startswith("ERROR") :
            return add_rule_to_db(request.data)
        return ufw_resp, 400

@app.route("/ufw/rules/<rule_id>", methods=["DELETE", "POST"])
def modify_rule(rule_id) :
    try :
        r = get_rule(int(rule_id))
        print(r)
    except IndexError :
        return "Non existing rule", 404

    if request.method == "POST" :
        data = request.data.strip()
        try :
            ufw_command(data)
        except subprocess.CalledProcessError :
            return "Syntax error", 400

    rules = delete_rule_from_db(rule_id)
    try :
        ufw_command("delete " + r)
    except subprocess.CalledProcessError :
        return "Syntax error", 400

    if request.method == "POST" :
        rules = add_rule_to_db(data, int(rule_id))
    return rules

def get_rules_from_db():
    return json.dumps(db.search(Rule.id > 0))

def get_rule(rule_id):
    return db.search(Rule.id == rule_id)[0]["rule"]

def add_rule_to_db(r, r_id=None):
    if r_id == None :
        #global id
        #id += 1
        #r_id = id
        try :
            r_id = db.all()[-1].eid + 1
        except IndexError :
            r_id = 1
    if db.count(Rule.rule == r) > 0 :
        pass
    else :
        db.insert({"rule" : r, "id" : r_id})
    return get_rules_from_db()

def delete_rule_from_db(rule_id):
    db.remove(Rule.id == int(rule_id))
    return get_rules_from_db()


def ufw_command(c) :
    command = ["ufw"] +  c.split(" ")
    #TODO add log
    print(command)
    return subprocess.check_output(command)

