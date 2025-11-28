#!/bin/bash

scriptPath=$(realpath $0)
scriptDir=$(dirname $scriptPath)

docker run \
  -v $scriptDir/../bin/netapply:/usr/local/bin/netapply \
  -v bird-run-vol:/var/run/bird \
  -v /var/run/netapply-local-test:/shared-socks \
  -v /etc/bird/ebgp_peers:/etc/bird/ebgp_peers \
  --rm \
  -it \
  --name netapply-test \
  debian:trixie \
  netapply \
  serve-local \
  --node=vie1 \
  --bind-unix-socket=/shared-socks/netapply-local.sock \
  --resolver-endpoint=1.1.1.1:53 \
  --v-6-available=true
