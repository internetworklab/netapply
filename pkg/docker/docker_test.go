package docker_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	pkgdocker "example.com/connector/pkg/docker"
	pkgutils "example.com/connector/pkg/utils"
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

// This test case does the following:
// 1. Create a container with image ubuntu:22.04
// 2. Sleep for 1 second
// 3. Change the image to ubuntu:24.04
// 4. Check if the container has been recreated with the new image
// 5. Stop and remove the container
func TestDockerReconcile(t *testing.T) {
	now := time.Now()
	containerName := fmt.Sprintf("container-%d", now.Unix())
	t.Logf("Using container name %s", containerName)

	image1 := "ubuntu:22.04"
	image2 := "ubuntu:24.04"
	dockerConfig := &pkgdocker.DockerContainerConfig{
		ContainerName: containerName,
		Image:         image1,
		Command:       []string{"/bin/bash"},
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	ctx := context.Background()
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	t.Logf("Creating container %s with image %s", containerName, image1)
	if err := dockerConfig.Create(ctx); err != nil {
		t.Fatalf("failed to apply docker config: %v", err)
	}

	t.Logf("Sleeping for 1 seconds")
	time.Sleep(1 * time.Second)

	t.Logf("Retrieving the container %s that is just created", containerName)
	cont, err := pkgdocker.FindContainer(ctx, cli, containerName)
	if err != nil {
		t.Fatalf("failed to find container: %v", err)
	}
	t.Logf("Found container %s that is just created, container id: %s, image: %s", containerName, cont.ID, cont.Image)

	t.Logf("Changing image to %s", image2)
	dockerConfig.Image = image2

	t.Logf("Apply the changed config")
	if err := dockerConfig.Apply(ctx); err != nil {
		t.Fatalf("failed to apply docker config: %v", err)
	}

	t.Logf("Sleeping for 1 seconds to wait for the change to take effect")
	time.Sleep(1 * time.Second)

	t.Logf("Try retrieving the re-created container %s", containerName)
	cont, err = pkgdocker.FindContainer(ctx, cli, containerName)
	if err != nil {
		t.Fatalf("failed to find container: %v", err)
	}
	if cont == nil {
		t.Fatalf("container is not found")
	}

	t.Logf("Found the re-created container %s, container id: %s, image: %s", containerName, cont.ID, cont.Image)

	if cont.Image != image2 {
		t.Fatalf("container image is not %s", image2)
	}

	t.Logf("Stopping and removing the test container %s", containerName)
	pkgdocker.StopAndRemoveContainer(ctx, containerName)
}
