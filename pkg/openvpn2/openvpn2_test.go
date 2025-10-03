package openvpn2_test

import (
	"context"
	"testing"
	"time"

	"github.com/docker/docker/client"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	openvpn2 "github.com/internetworklab/netapply/pkg/openvpn2"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func TestOpenVPN2ContainerCreateAndRemoval(t *testing.T) {

	// Strategy:
	// 1. Create the container
	// 2. Extract the container id and state
	// 3. Check that the state is "running"
	// 4. Stop the container
	// 5. If the container still exists, remote the container
	// 6. Confirm that the container is really removed

	ovpInst := new(openvpn2.OpenVPN2Instance)
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

	// slepping 3 seconds for container to be initialized

	time.Sleep(3 * time.Second)

	// checking if the container is running
	cont, err := pkgdocker.FindContainer(ctx, cli, ovpInst.Name)
	if err != nil {
		t.Fatalf("failed to find openvpn2 container: %v", err)
	}
	if cont == nil {
		t.Fatalf("openvpn2 container %s not found", ovpInst.Name)
	}

	contId := cont.ID
	contState := cont.State
	t.Logf("openvpn2 container %s found, container id: %s, container state: %s", ovpInst.Name, contId, contState)

	if contState != "running" {
		t.Fatalf("openvpn2 container %s is not running, container state: %s", ovpInst.Name, contState)
	}

	t.Logf("Stopping openvpn2 container %s", ovpInst.Name)
	err = pkgdocker.StopAndRemoveContainer(ctx, ovpInst.Name)
	if err != nil {
		t.Fatalf("failed to stop and remove openvpn2 container: %v", err)
	}

	// sleeping 3 seconds for container to be stopped and removed
	time.Sleep(3 * time.Second)

	// checking if the container is removed
	cont, err = pkgdocker.FindContainer(ctx, cli, ovpInst.Name)
	if err != nil {
		t.Fatalf("failed to find openvpn2 container: %v", err)
	}
	if cont != nil {
		t.Fatalf("openvpn2 container %s is not removed", ovpInst.Name)
	}

	t.Logf("OpenVPN2 container %s is successfully created, stopped and removed", ovpInst.Name)
}
