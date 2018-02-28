#!/bin/bash

#Verify root
if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
        exit
fi

echo "Start lek process time: $(date)"


export user="ubuntu"

#Folder where store the libraries
export SRC_DIR=/usr/local/lib

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_DIR="$SCRIPT_DIR/configs"

cd $SRC_DIR

add-apt-repository -y ppa:openjdk-r/ppa
apt-get -y update
apt-get -y install openjdk-8-jdk


echo "Start Logstash installation time: $(date)"

############
# Logstash #
############

export logstash_version="logstash-5.2.2"

wget -qO- https://artifacts.elastic.co/downloads/logstash/$logstash_version.tar.gz | tar xvz

cd $logstash_version

# Configuration file
# Listen to port specified inside default-conf.conf waiting for syslog messages
cp -f $CONFIG_DIR/default-conf.conf config/default-conf.conf

ln -s $SRC_DIR/$logstash_version/bin/logstash /usr/local/bin/logstash

echo "Start Elasticsearch installation time: $(date)"

#################
# Elasticsearch #
#################

cd $SRC_DIR

export elastic_version="elasticsearch-5.2.2"
wget -qO- https://artifacts.elastic.co/downloads/elasticsearch/$elastic_version.tar.gz | tar xvz
cd $elastic_version

# Configuration File
mkdir -p /usr/local/lib/elasticsearch-5.2.2/config
cp $CONFIG_DIR/elasticsearch.yml /usr/local/lib/elasticsearch-5.2.2/config/

ln -s $SRC_DIR/$elastic_version/bin/elasticsearch /usr/local/bin/elasticsearch

echo "Start Kibana installation time: $(date)"

##########
# Kibana #
##########
cd $SRC_DIR

export kibana_version="kibana-5.2.2-linux-x86_64"
wget -qO- https://artifacts.elastic.co/downloads/kibana/$kibana_version.tar.gz | tar xvz #-C $SRC_DIR
cd $kibana_version

#Copy config file to the correct directory
cp $CONFIG_DIR/kibana.yaml /home/$user/

ln -s $SRC_DIR/$kibana_version/bin/kibana /usr/local/bin/kibana

echo "LEK installation completed time: $(date)"

#########
# Nginx #
#########

apt-get -y install nginx


########################
# User creation server #
########################

apt-get -y install python-pip

pip -y install --upgrade setuptools

pip -y install Flask

echo "Flask installation completed time: $(date)"

#########
# Start #
#########

chown -R $user:$user $SRC_DIR/$elastic_version $SRC_DIR/$logstash_version $SRC_DIR/$kibana_version

#TODO: start: Attenzione! Ci mette 10 min a partire
export s_name="MonitorScreen"
su $user -c "screen -m -d -S $s_name"
su $user -c "screen -S $s_name -p 0 -X stuff 'screen logstash -f $SRC_DIR/$logstash_version/config/default-conf.conf\n'"
su $user -c "screen -S $s_name -p 0 -X stuff 'screen elasticsearch\n'"
su $user -c "screen -S $s_name -p 0 -X stuff 'screen kibana -H \"0.0.0.0\" -c /home/$user/kibana.yml\n'"
