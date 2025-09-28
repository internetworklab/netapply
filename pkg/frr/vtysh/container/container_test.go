package container_test

import (
	"context"
	"testing"

	pkgfrrvtyshcontainer "example.com/connector/pkg/frr/vtysh/container"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/client"
)

func TestContainerVtyshConfigWriter(t *testing.T) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	containerName := "frr"
	vrf := "v1"
	routerID := "1.2.3.4"
	commands := []string{
		"configure",
		"router ospf vrf " + vrf,
		"ospf router-id " + routerID,
		"exit",
	}

	writer, err := pkgfrrvtyshcontainer.NewContainerVtyshConfigWriter(ctx, containerName, nil)
	if err != nil {
		t.Fatalf("failed to create container vtysh config writer: %v", err)
	}
	defer writer.Close()

	if err := writer.WriteCommands(ctx, commands); err != nil {
		t.Fatalf("failed to write commands: %v", err)
	}
}
