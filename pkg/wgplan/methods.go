package wgplan

import (
	"fmt"
	"os"
	"path"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (plan *WGPlan) Generate(plaintextKeys, noKeysOutput bool, keysOutDir string) error {

	connections := make(map[string]map[string]*WGConnection)

	for from, conns := range plan.Connections {
		connIdx := 0
		for to, connraw := range conns {
			var conn *WGConnection = connraw
			if conn == nil {
				conn = new(WGConnection)
				connID := fmt.Sprintf("%s-%s", from, to)
				conn.ConnectionID = &connID
			}
			if _, ok := connections[from]; !ok {
				connections[from] = make(map[string]*WGConnection)
			}
			connections[from][to] = conn

			pkObj, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return fmt.Errorf("failed to generate private key: %w", err)
			}

			privkeyStr := pkObj.String()
			if plaintextKeys {
				conn.SelfPrivateKey = &privkeyStr
			}

			if !noKeysOutput {
				os.MkdirAll(keysOutDir, 0755)
				fileName := fmt.Sprintf("%s.key", *conn.ConnectionID)
				filePath := path.Join(keysOutDir, fileName)
				if err := os.WriteFile(filePath, []byte(privkeyStr), 0644); err != nil {
					return fmt.Errorf("failed to write key file: %w", err)
				}
				conn.SelfPrivateKeyFile = &filePath
			}

			conn.SelfPublicKey = pkObj.PublicKey().String()

			if fromNode, ok := plan.Nodes[from]; ok {
				if fromNode.ListenPortBase != nil {
					lp := *fromNode.ListenPortBase + connIdx
					conn.SelfListenPort = &lp
				}
			}
			connIdx++
		}
	}

	plan.Connections = connections

	getRevConn := func(from, to string) *WGConnection {
		if conns, ok := plan.Connections[to]; ok {
			if conn, ok := conns[from]; ok {
				return conn
			}
		}
		return nil
	}

	for from, conns := range plan.Connections {
		for to, conn := range conns {
			if revConn := getRevConn(from, to); revConn != nil {
				conn.PeerPublicKey = revConn.SelfPublicKey

				if toNode, ok := plan.Nodes[to]; ok {
					if revConn.SelfListenPort != nil {
						conn.PeerEndpointHost = toNode.EndpointHost
						conn.PeerEndpointPort = revConn.SelfListenPort
					}
				}

				plan.IndexedConnections[*conn.ConnectionID] = conn
			}
		}
	}

	// verifying
	for from, conns := range plan.Connections {
		for to, conn := range conns {
			revConn := getRevConn(from, to)
			if revConn == nil {
				return fmt.Errorf("no reverse connection found for %s-%s", from, to)
			}
			if conn.PeerPublicKey != revConn.SelfPublicKey {
				return fmt.Errorf("peer public key mismatch for %s-%s: %s != %s", from, to, conn.PeerPublicKey, revConn.SelfPublicKey)
			}
			if conn.SelfPublicKey != revConn.PeerPublicKey {
				return fmt.Errorf("self public key mismatch for %s-%s: %s != %s", from, to, conn.SelfPublicKey, revConn.PeerPublicKey)
			}

			fromNode, ok := plan.Nodes[from]
			if !ok {
				return fmt.Errorf("from node %s not found", from)
			}

			toNode, ok := plan.Nodes[to]
			if !ok {
				return fmt.Errorf("to node %s not found", to)
			}

			if fromNode.EndpointHost != nil && fromNode.ListenPortBase != nil {
				if revConn.PeerEndpointHost == nil {
					return fmt.Errorf("peer endpoint host is nil for %s-%s", from, to)
				}
				if *revConn.PeerEndpointHost != *fromNode.EndpointHost {
					return fmt.Errorf("peer endpoint host mismatch for %s-%s: %s != %s", from, to, *revConn.PeerEndpointHost, *fromNode.EndpointHost)
				}
				if revConn.PeerEndpointPort == nil {
					return fmt.Errorf("peer endpoint port is nil for %s-%s", from, to)
				}
				if *revConn.PeerEndpointPort != *conn.SelfListenPort {
					return fmt.Errorf("peer endpoint port mismatch for %s-%s: %d != %d", from, to, *revConn.PeerEndpointPort, conn.SelfListenPort)
				}
			}

			if toNode.EndpointHost != nil && toNode.ListenPortBase != nil {
				if conn.PeerEndpointHost == nil {
					return fmt.Errorf("peer endpoint host is nil for %s-%s", from, to)
				}
				if *conn.PeerEndpointHost != *toNode.EndpointHost {
					return fmt.Errorf("peer endpoint host mismatch for %s-%s: %s != %s", from, to, *conn.PeerEndpointHost, *toNode.EndpointHost)
				}
				if conn.PeerEndpointPort == nil {
					return fmt.Errorf("peer endpoint port is nil for %s-%s", from, to)
				}
				if *conn.PeerEndpointPort != *revConn.SelfListenPort {
					return fmt.Errorf("peer endpoint port mismatch for %s-%s: %d != %d", from, to, *conn.PeerEndpointPort, revConn.SelfListenPort)
				}
			}
		}
	}

	return nil
}
