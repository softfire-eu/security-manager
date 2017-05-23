#!/bin/bash

export monitor_address=$1
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
log_dir=/var/log/openbaton/security

#TODO Setup Logging

apt-get -y install ufw

bash $SCRIPT_DIR/start_server.sh &> $log_dir/start_server.log & 

# Wait for Flask server to start

http_proxy=''

curl http://localhost:5000/ufw/rules
while [ "$?" -eq 7 ]; do
    sleep 1
    curl http://localhost:5000/ufw/rules
done

#I configure the firewall through the APIs (I keep TinyDB consistent with status)
curl -X POST -H "Content-Type: text/plain" -d 'allow from any to any port ssh' http://localhost:5000/ufw/rules
curl -X POST -H "Content-Type: text/plain" -d 'allow from any to any port 5000' http://localhost:5000/ufw/rules

#ufw allow ssh
#ufw --force enable
ufw status

