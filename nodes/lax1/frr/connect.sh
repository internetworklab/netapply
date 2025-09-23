#!/bin/bash

scriptPath=$(realpath $0)
scriptDir=$(dirname $scriptPath)

cd $scriptDir

./connect/connect_openvpn.sh

#connect wg
for wgConf in $scriptDir/connect/wg/*.conf; do
    go run ./connect/connect_wg.go $wgConf
done

ns2=$(docker inspect $container2 --format {{.NetworkSettings.SandboxKey}})
if [ -z "$ns2" ]; then
    echo "ns2 not found"
    exit 1
fi

# connect dummy
$ipcmd2 l add v5-dummy type dummy &> /dev/null
$ipcmd2 l set v5-dummy up
$ipcmd2 a add 10.3.64.1/24 dev v5-dummy &> /dev/null

# setup bridge
$ipcmd2 l add br42 type bridge &> /dev/null
$ipcmd2 l set br42 up

# connect vxlan
$ipcmd2 l add vx42 type vxlan id 42 local 10.3.64.1 dstport 4789 nolearning &> /dev/null
$ipcmd2 l set vx42 up
$ipcmd2 l set vx42 master br42

# configure ospf
docker exec $container2 vtysh -f /etc/frr/routers/ospf.conf

# configure bgp
docker exec $container2 vtysh -f /etc/frr/routers/bgp.conf
