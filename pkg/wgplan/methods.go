package wgplan

import (
	"fmt"

	"net"
	"strconv"

	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func getFromMap(m map[string]map[string]*WGConnection, from, to string) *WGConnection {
	if conns, ok := m[from]; ok {
		if conn, ok := conns[to]; ok {
			return conn
		}
	}
	return nil
}

func setToMap(m map[string]map[string]*WGConnection, from, to string, conn *WGConnection) {
	if _, ok := m[from]; !ok {
		m[from] = make(map[string]*WGConnection)
	}
	m[from][to] = conn
}

// Map connection ID to private key
type PrivateKeysMap = map[string]string

func (plan *WGPlan) Generate(plaintextKeys bool) (privateKeys PrivateKeysMap, err error) {
	privateKeys = make(PrivateKeysMap)

	if plan.Nodes == nil {
		return nil, fmt.Errorf("nodes is nil")
	}

	localIPsMap := make(map[string]string)
	for nodename, node := range plan.Nodes {
		if node.LocalIP != nil {
			if anotherNode, ok := localIPsMap[*node.LocalIP]; ok && anotherNode != nodename {
				return nil, fmt.Errorf("node %s is trying to use local ip %s, but it is already used by another node %s", nodename, *node.LocalIP, anotherNode)
			}
			localIPsMap[*node.LocalIP] = nodename
		}
	}

	connections := make(map[string]map[string]*WGConnection)
	for from, conns := range plan.Connections {
		for to, connraw := range conns {
			var conn *WGConnection = connraw
			if conn == nil {
				conn = new(WGConnection)
				connID := fmt.Sprintf("%s-%s", from, to)
				conn.ConnectionID = &connID
			}
			setToMap(connections, from, to, conn)
			var revConn *WGConnection = getFromMap(plan.Connections, to, from)
			if revConn == nil {
				// automatically creates the reverse link
				revConn = new(WGConnection)
				connID := fmt.Sprintf("%s-%s", to, from)
				revConn.ConnectionID = &connID
			}
			setToMap(connections, to, from, revConn)
		}
	}
	plan.Connections = connections

	for from, conns := range plan.Connections {
		connIdx := 0
		for _, conn := range conns {

			pkObj, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return nil, fmt.Errorf("failed to generate private key: %w", err)
			}

			privkeyStr := pkObj.String()
			privateKeys[*conn.ConnectionID] = privkeyStr

			if plaintextKeys {
				conn.SelfPrivateKey = &privkeyStr
			}

			conn.SelfPublicKey = pkObj.PublicKey().String()

			if fromNode, ok := plan.Nodes[from]; ok {
				conn.LocalIP = fromNode.LocalIP
				if fromNode.ListenPortBase != nil {
					lp := *fromNode.ListenPortBase + connIdx
					conn.SelfListenPort = &lp
				}
			}
			connIdx++
		}
	}

	for from, conns := range plan.Connections {
		for to, conn := range conns {
			revConn := getFromMap(plan.Connections, to, from)
			if revConn != nil {
				conn.PeerPublicKey = revConn.SelfPublicKey
				if toNode, ok := plan.Nodes[to]; ok {
					conn.PeerIP = toNode.LocalIP
					if revConn.SelfListenPort != nil {
						conn.PeerEndpointHost = toNode.EndpointHost
						conn.PeerEndpointPort = revConn.SelfListenPort
					}
				}
			}
		}
	}

	// verifying
	for from, conns := range plan.Connections {
		for to, conn := range conns {
			revConn := getFromMap(plan.Connections, to, from)
			if revConn == nil {
				return nil, fmt.Errorf("no reverse connection found for %s-%s", from, to)
			}
			if conn.PeerPublicKey != revConn.SelfPublicKey {
				return nil, fmt.Errorf("peer public key mismatch for %s-%s: %s != %s", from, to, conn.PeerPublicKey, revConn.SelfPublicKey)
			}
			if conn.SelfPublicKey != revConn.PeerPublicKey {
				return nil, fmt.Errorf("self public key mismatch for %s-%s: %s != %s", from, to, conn.SelfPublicKey, revConn.PeerPublicKey)
			}

			fromNode, ok := plan.Nodes[from]
			if !ok {
				return nil, fmt.Errorf("from node %s not found", from)
			}

			toNode, ok := plan.Nodes[to]
			if !ok {
				return nil, fmt.Errorf("to node %s not found", to)
			}

			var fromNodeIsNAT bool = false
			if fromNode.EndpointHost == nil || fromNode.ListenPortBase == nil {
				fromNodeIsNAT = true
			}

			var toNodeIsNAT bool = false
			if toNode.EndpointHost == nil || toNode.ListenPortBase == nil {
				toNodeIsNAT = true
			}

			if fromNodeIsNAT && toNodeIsNAT {
				return nil, fmt.Errorf("both nodes %s and %s are NAT nodes", from, to)
			}

			if fromNode.EndpointHost != nil && fromNode.ListenPortBase != nil {
				if revConn.PeerEndpointHost == nil {
					return nil, fmt.Errorf("peer endpoint host is nil for %s-%s", from, to)
				}
				if *revConn.PeerEndpointHost != *fromNode.EndpointHost {
					return nil, fmt.Errorf("peer endpoint host mismatch for %s-%s: %s != %s", from, to, *revConn.PeerEndpointHost, *fromNode.EndpointHost)
				}
				if revConn.PeerEndpointPort == nil {
					return nil, fmt.Errorf("peer endpoint port is nil for %s-%s", from, to)
				}
				if *revConn.PeerEndpointPort != *conn.SelfListenPort {
					return nil, fmt.Errorf("peer endpoint port mismatch for %s-%s: %d != %d", from, to, *revConn.PeerEndpointPort, conn.SelfListenPort)
				}
			}

			if toNode.EndpointHost != nil && toNode.ListenPortBase != nil {
				if conn.PeerEndpointHost == nil {
					return nil, fmt.Errorf("peer endpoint host is nil for %s-%s", from, to)
				}
				if *conn.PeerEndpointHost != *toNode.EndpointHost {
					return nil, fmt.Errorf("peer endpoint host mismatch for %s-%s: %s != %s", from, to, *conn.PeerEndpointHost, *toNode.EndpointHost)
				}
				if conn.PeerEndpointPort == nil {
					return nil, fmt.Errorf("peer endpoint port is nil for %s-%s", from, to)
				}
				if *conn.PeerEndpointPort != *revConn.SelfListenPort {
					return nil, fmt.Errorf("peer endpoint port mismatch for %s-%s: %d != %d", from, to, *conn.PeerEndpointPort, revConn.SelfListenPort)
				}
			}

			if fromNode.LocalIP != nil {
				if conn.LocalIP == nil {
					return nil, fmt.Errorf("local ip is nil for %s-%s", from, to)
				}
				if *conn.LocalIP != *fromNode.LocalIP {
					return nil, fmt.Errorf("local ip mismatch for %s-%s: %s != %s", from, to, *conn.LocalIP, *fromNode.LocalIP)
				}
				if revConn.PeerIP == nil {
					return nil, fmt.Errorf("peer ip is nil for %s-%s", from, to)
				}
				if *revConn.PeerIP != *fromNode.LocalIP {
					return nil, fmt.Errorf("peer ip mismatch for %s-%s: %s != %s", from, to, *revConn.PeerIP, *toNode.LocalIP)
				}
			}

			if toNode.LocalIP != nil {
				if conn.PeerIP == nil {
					return nil, fmt.Errorf("peer ip is nil for %s-%s", from, to)
				}
				if *conn.PeerIP != *toNode.LocalIP {
					return nil, fmt.Errorf("peer ip mismatch for %s-%s: %s != %s", from, to, *conn.PeerIP, *toNode.LocalIP)
				}
				if revConn.LocalIP == nil {
					return nil, fmt.Errorf("local ip is nil for %s-%s", from, to)
				}
				if *revConn.LocalIP != *toNode.LocalIP {
					return nil, fmt.Errorf("peer local ip mismatch for %s-%s: %s != %s", from, to, *revConn.LocalIP, *toNode.LocalIP)
				}
			}
		}
	}

	if plan.IndexedConnections == nil {
		plan.IndexedConnections = make(map[string]*WGConnection)
	}
	for _, conns := range plan.Connections {
		for _, conn := range conns {
			plan.IndexedConnections[*conn.ConnectionID] = conn
		}
	}

	return privateKeys, nil
}

func (plan *WGPlan) ToWgConfs(privateKeys PrivateKeysMap) (map[string][]*pkginterfacewireguard.WireGuardConfig, error) {
	wgConfs := make(map[string][]*pkginterfacewireguard.WireGuardConfig)
	for nodename := range plan.Nodes {
		if _, ok := wgConfs[nodename]; !ok {
			wgConfs[nodename] = make([]*pkginterfacewireguard.WireGuardConfig, 0)
		}
		if conns, ok := plan.Connections[nodename]; ok {
			for to, conn := range conns {
				wgConf := &pkginterfacewireguard.WireGuardConfig{}
				wgConf.Name = fmt.Sprintf("w-%s-%s", nodename, to)
				privk, found := privateKeys[*conn.ConnectionID]
				if !found {
					return nil, fmt.Errorf("private key not found for connection %s-%s", nodename, to)
				}
				wgConf.PrivateKey = privk
				if conn.SelfListenPort != nil {
					wgConf.ListenPort = conn.SelfListenPort
				}
				peerCfg := &pkginterfacewireguard.WireGuardPeerConfig{
					PublicKey:  conn.PeerPublicKey,
					AllowedIPs: []string{"0.0.0.0/0", "::/0"},
				}
				if conn.PeerEndpointHost != nil && conn.PeerEndpointPort != nil {
					ep := net.JoinHostPort(*conn.PeerEndpointHost, strconv.Itoa(*conn.PeerEndpointPort))
					peerCfg.Endpoint = &ep
				}
				if conn.LocalIP != nil && conn.PeerIP != nil {
					peerIPCIDR := pkgutils.WithFullMask(conn.PeerIP)
					if peerIPCIDR == nil {
						return nil, fmt.Errorf("peer ip %s is invalid", *conn.PeerIP)
					}
					addrCfg := &pkginterfacecommon.AddressConfig{
						Local: conn.LocalIP,
						Peer:  peerIPCIDR,
					}
					wgConf.Addresses = []pkginterfacecommon.AddressConfig{*addrCfg}
				}

				wgConf.Peers = []pkginterfacewireguard.WireGuardPeerConfig{*peerCfg}
				wgConfs[nodename] = append(wgConfs[nodename], wgConf)
			}
		}
	}
	return wgConfs, nil
}
