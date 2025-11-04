#!/bin/bash

for nodename in ams1 fra1 nyc1 lax1 sgp1 tyo1 vie1 hkg1; do
    echo "nodename:" $nodename
    go run main.go --from-directory ../services/bird/$nodename/conf.d/peers >../services/bird/$nodename/peers.yaml
    mkdir -p ../services/bird/$nodename/conf.d/peers
    rm -rf ../services/bird/$nodename/conf.d/peers/*
    go run main.go --from-yaml ../services/bird/$nodename/peers.yaml --to-directory ../services/bird/$nodename/conf.d/peers
done
