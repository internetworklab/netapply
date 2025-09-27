package openvpn2_test

import (
	"context"
	"os"
	"testing"

	openvpn2 "example.com/connector/pkg/openvpn2"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v3"
)

func TestOpenVPN2ServerCreate(t *testing.T) {
	filepath := "../../examples/openvpn-container-server.yaml"
	ovpInst := new(openvpn2.OpenVPN2Instance)
	file, err := os.Open(filepath)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	if err := yaml.NewDecoder(file).Decode(ovpInst); err != nil {
		t.Fatalf("Failed to decode OpenVPN2 instance: %v", err)
	}

	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	serviceName := "openvpn-server"

	ctx = pkgutils.SetServiceNameInCtx(ctx, serviceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	t.Logf("Creating container %s using service name %s ...", ovpInst.DockerContainer.ContainerName, serviceName)
	if err := ovpInst.Create(ctx); err != nil {
		t.Fatalf("Failed to create OpenVPN2 instance: %v", err)
	}
}
