#!/bin/bash

container1="openvpn-server"
container2="frr"

pid1=$(docker inspect $container1 --format {{.State.Pid}})
pid2=$(docker inspect $container2 --format {{.State.Pid}})
echo "pid1: $pid1"
echo "pid2: $pid2"

ip l add veth1 netns $pid1 type veth peer name veth1 netns $pid2 &> /dev/null

ns1=$(docker inspect $container1 --format {{.NetworkSettings.SandboxKey}})
ns2=$(docker inspect $container2 --format {{.NetworkSettings.SandboxKey}})
echo "ns1: $ns1"
echo "ns2: $ns2"    

ipcmd1="nsenter --net=$ns1 ip"
ipcmd2="nsenter --net=$ns2 ip"

$ipcmd1 l set veth1 up
$ipcmd2 l set veth1 up

$ipcmd1 l add br0 type bridge &> /dev/null
$ipcmd1 l set br0 up
$ipcmd1 l set veth1 master br0
$ipcmd1 l set tap0 master br0
$ipcmd1 l set tap0 up

$ipcmd2 a add 10.9.0.1 peer 10.9.0.2/32 dev veth1 &> /dev/null

$ipcmd2 l add v5-dummy type dummy &> /dev/null
$ipcmd2 l set v5-dummy up
$ipcmd2 a add 10.3.64.1/24 dev v5-dummy &> /dev/null

docker exec $container2 vtysh -f /misc/ospf.conf
