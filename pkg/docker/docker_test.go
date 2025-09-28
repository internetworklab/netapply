package docker_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	pkgdocker "example.com/connector/pkg/docker"
	"github.com/docker/docker/client"
)

func TestDockerListingNoMatched(t *testing.T) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	now := time.Now()

	containerName := fmt.Sprintf("%d", now.Unix())
	t.Logf("Finding unmatched container: %s", containerName)

	cont, err := pkgdocker.FindContainer(ctx, cli, containerName)
	if err != nil {
		t.Fatalf("failed to find container: %v, but this shouldn't be an error", err)
	}
	if cont != nil {
		t.Fatalf("container is found: %v, which is not expected", cont)
	}
}
