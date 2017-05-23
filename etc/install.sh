#!/bin/bash

export SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export log_dir=/var/log/openbaton/security

mkdir $log_dir

apt-get -y install python-pip

pip install -U setuptools
pip install Flask tinydb requests

#############################################################
# Activate Forwarding                                       #
# Necessary when the VM is dedicated and in SDN environment #
# OK for UFW and for Suricata working in IDS mode           #
# If want Suricata in IPS mode need to use NFQUEUE          #
#############################################################
sysctl -w net.ipv4.ip_forward=1

# Disable sending of redirect
echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects

bash $SCRIPT_DIR/ufw.sh &> $log_dir/ufw.log & 
