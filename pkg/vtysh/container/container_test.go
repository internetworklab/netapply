package container_test

import (
	"context"
	"testing"

	pkgutils "example.com/connector/pkg/utils"
	"example.com/connector/pkg/vtysh/container"
	"github.com/docker/docker/client"
)

func TestContainerVtyshConfigWriter(t *testing.T) {
	writer := container.NewContainerVtyshConfigWriter("test-container")
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	writer.WriteCommands(ctx, []string{"show ip route"})
}
