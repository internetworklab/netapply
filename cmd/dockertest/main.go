package main

import (
	"context"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

func main() {

	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	serviceName := "test-ubuntu"

	ctx = pkgutils.SetServiceNameInCtx(ctx, serviceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	containerName := "test-ubuntu"
	image := "ubuntu:22.04"

	containerConfig := &container.Config{
		Image:     image,
		Cmd:       []string{"/bin/bash"},
		Tty:       true,
		OpenStdin: true,
	}
	hostConfig := &container.HostConfig{
		AutoRemove: true,
	}
	networkConfig := &network.NetworkingConfig{}

	resp, err := cli.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		networkConfig,
		nil,
		containerName,
	)

	if err != nil {
		log.Fatalf("failed to create container: %v", err)
	}

	log.Printf("Container created: %v", resp.ID)

	err = cli.ContainerStart(ctx, resp.ID, container.StartOptions{})
	if err != nil {
		log.Fatalf("failed to start container: %v", err)
	}

	log.Printf("Container started: %v", resp.ID)

	// Attach to the container
	log.Printf("Attaching to container: %v", resp.ID)

	attachResp, err := cli.ContainerAttach(ctx, resp.ID, container.AttachOptions{
		Stream: true,
		Stdin:  true,
		Stdout: true,
		Stderr: true,
	})
	if err != nil {
		log.Fatalf("failed to attach to container: %v", err)
	}
	defer attachResp.Close()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start goroutines for piping data
	go func() {
		io.Copy(attachResp.Conn, os.Stdin)
	}()

	go func() {
		io.Copy(os.Stdout, attachResp.Reader)
	}()

	// Wait for signal to exit
	<-sigChan
	log.Printf("Received signal, stopping container...")

	// Stop the container
	err = cli.ContainerStop(ctx, resp.ID, container.StopOptions{})
	if err != nil {
		log.Printf("failed to stop container: %v", err)
	}

	// Remove the container
	err = cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{})
	if err != nil {
		log.Printf("failed to remove container: %v", err)
	}

	log.Printf("Container stopped and removed")

}
