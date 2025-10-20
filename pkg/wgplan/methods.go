package wgplan

import (
	"fmt"

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

func (plan *WGPlan) Generate(plaintextKeys bool) (privateKeys map[string]string, err error) {
	privateKeys = make(map[string]string)

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
