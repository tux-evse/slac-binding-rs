#!/bin/bash

export LD_LIBRARY_PATH=/usr/local/lib64
pkill afb-slac
cynagora-admin set '' 'HELLO' '' '*' yes
clear

# build test config dirname
DIRNAME=`dirname $0`
cd $DIRNAME/..
CONFDIR=`pwd`/etc

DEVTOOL_PORT=1238
echo Slac debug mode config=$CONFDIR/*.json port=$DEVTOOL_PORT

afb-binder --name=afb-slac --port=$DEVTOOL_PORT -v \
  --config=$CONFDIR/binder-slac.json \
  --config=$CONFDIR/binding-slac.json \
  --config=$CONFDIR/binding-am62x.json \
  --config=$CONFDIR/binding-i2c.json \
  $*