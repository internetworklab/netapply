#!/bin/bash

docker exec -dit openvpn-client \
    openvpn  --config /etc/openvpn/client.conf

docker exec -it openvpn-client ip a add fe80::1772/64 dev tap0 noprefixroute

docker exec -dit openvpn-server \
    openvpn  --config /etc/openvpn/server.conf

docker exec -it openvpn-server ip a add fe80::1771/64 dev tap0 noprefixroute
