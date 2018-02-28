#!/bin/bash

logdir=/var/log/openbaton/security_monitor

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )" #Script's dir

mkdir $logdir
nohup bash $DIR/lek-start.sh > $logdir/lek-start.log &
