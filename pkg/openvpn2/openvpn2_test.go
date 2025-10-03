package openvpn2_test

import (
	"context"
	"testing"

	openvpn2 "example.com/connector/pkg/openvpn2"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/client"
)

func TestOpenVPN2ContainerCreateAndRemoval(t *testing.T) {
	// todo: rewrite such test
	// Strategy:
	// 1. Create the container
	// 2. Extract the container id and state
	// 3. Check that the state is "running"
	// 4. Stop the container
	// 5. If the container still exists, remote the container
	// 6. Confirm that the container is really removed

	ovpInst := new(openvpn2.OpenVPN2Instance)
	ovpInst.Server = true
	ovpInst.Port = new(int)
	*ovpInst.Port = 1194
	ovpInst.Dev = "tap0"
	ovpInst.Proto = openvpn2.OpenVPN2ProtoTCPServer
	ovpInst.TLSServer = new(bool)
	*ovpInst.TLSServer = true
	ovpInst.Name = "openvpn-connector"
	ovpInst.Image = "openvpn:latest"

	// Providing tls x509v2 cert and map it to the container
	ovpInst.CertFile = "/etc/openvpn/certs/cert.pem"
	ovpInst.HostTLSCertFile = "/root/certs/openvpn/server/cert.pem"

	// Providing tls x509v2 key and map it to the container
	ovpInst.KeyFile = "/etc/openvpn/certs/key.pem"
	ovpInst.HostTLSKeyFile = "/root/certs/openvpn/server/key.pem"

	// Providing dh pem file and map it to the container
	ovpInst.DHPEMFile = new(string)
	*ovpInst.DHPEMFile = "/etc/openvpn/certs/dh.pem"
	ovpInst.HostDHPEMFile = new(string)
	*ovpInst.HostDHPEMFile = "/root/certs/openvpn/server/dh.pem"

	ovpInst.PeerFingerprint = "06:00:DD:D5:77:82:A0:E6:E5:5F:C4:A0:F5:D3:5A:98:23:6E:E5:DC:86:D3:AB:60:9F:01:1B:97:D4:A6:60:BE"
	ovpInst.Topology = new(openvpn2.OpenVPN2Topology)
	*ovpInst.Topology = openvpn2.OpenVPN2TopologySubnet
	ovpInst.ServerBridge = new(bool)
	*ovpInst.ServerBridge = true
	ovpInst.ClientToClient = new(bool)
	*ovpInst.ClientToClient = true
	ovpInst.KeepaliveIntvSecs = new(openvpn2.OpenVPN2KeepaliveConfig)
	ovpInst.KeepaliveIntvSecs.IntervalSecs = 10
	ovpInst.KeepaliveIntvSecs.PatienceSecs = 120
	ovpInst.PersistTun = true
	ovpInst.StatusFile = []string{"openvpn-status.log"}
	ovpInst.ExplicitExitNotify = new(bool)
	*ovpInst.ExplicitExitNotify = true
	ovpInst.Verb = new(int)
	*ovpInst.Verb = 3
	ovpInst.AutoRemove = new(bool)
	*ovpInst.AutoRemove = false
	ovpInst.TTY = new(bool)
	*ovpInst.TTY = true
	ovpInst.OpenStdin = new(bool)
	*ovpInst.OpenStdin = true

	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	serviceName := "test-openvpn2"
	ctx = pkgutils.SetServiceNameInCtx(ctx, serviceName)

	if err := ovpInst.Create(ctx); err != nil {
		t.Fatalf("failed to create openvpn2 container: %v", err)
	}
}
