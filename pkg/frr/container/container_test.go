package container_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/docker/docker/client"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgfrrcontainer "github.com/internetworklab/netapply/pkg/frr/container"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

// To test, simply invoke `go test -v --run TestDefaultFRRContainerConfig ./pkg/frr/container`

func TestDefaultFRRContainerConfig(t *testing.T) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	now := time.Now()
	testFRRContainerName := fmt.Sprintf("frr-%d", now.Unix())
	t.Logf("Using test FRR container name %s", testFRRContainerName)

	containerConfig := pkgfrrcontainer.DefaultFRRContainerConfig()
	containerConfig.ContainerName = testFRRContainerName

	t.Logf("Starting tester FRR container %s", testFRRContainerName)

	err = containerConfig.Apply(ctx)
	if err != nil {
		t.Fatalf("failed to apply FRR container config: %v", err)
	}

	t.Logf("Wait for 5 seconds for the FRR container to start up")
	time.Sleep(5 * time.Second)

	cont, err := pkgdocker.FindContainer(ctx, cli, testFRRContainerName)
	if err != nil {
		t.Fatalf("failed to find FRR container: %v", err)
	}
	if cont == nil {
		t.Fatalf("FRR container %s not found", testFRRContainerName)
	}

	t.Logf("Found FRR container %s, container id: %s, image: %s", testFRRContainerName, cont.ID, cont.Image)

	t.Logf("Cleaning up the test FRR container %s", testFRRContainerName)
	err = pkgdocker.StopAndRemoveContainer(ctx, testFRRContainerName)
	if err != nil {
		t.Fatalf("failed to stop and remove FRR container: %v", err)
	}
}
