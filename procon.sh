#!/usr/bin/env bash

set -e

server=$1

if [ -z "$server" ]
then
	echo "Usage: $0 <server>"
	exit 1
fi

BINARIES_AGE=48

tmpd=`ssh $server "mktemp -d"`
r=$?

if ((r))
then
	echo "Failed 'mktemp -d' at $server."
	echo $tmpd
	exit $r
fi

scp -q procon.py procon.cfg procon.tactel.cfg procon.$server.cfg $server:$tmpd

set +e
ssh $server sudo $tmpd/procon.py -p $tmpd/procon.cfg #-p $tmpd/procon.tactel.cfg -p $tmpd/procon.$server.cfg
r=$?
set -e

echo $r

ssh $server "rm -f $tmpd/*"
ssh $server "rmdir $tmpd"

