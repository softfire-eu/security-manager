#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
log_dir=/var/log/openbaton/security

export FLASK_APP=$SCRIPT_DIR/api-server.py
#echo $SCRIPT_DIR
#cd $SCRIPT_DIR
#export FLASK_DEBUG=1
#export FLASK_APP=api-server.py

/usr/local/bin/flask &> /dev/null
while [ "$?" -eq 127 ]; do
    /usr/local/bin/flask &> /dev/null
done

/usr/local/bin/flask run --host=0.0.0.0 &> $log_dir/api-server.log &
