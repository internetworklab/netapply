package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"os"
	"strings"
	"time"

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

	// 1. Create exec on the container with /usr/bin/cat command
	log.Printf("Creating exec for /usr/bin/cat command")
	execResp, err := cli.ContainerExecCreate(ctx, resp.ID, container.ExecOptions{
		Cmd:          []string{"/usr/bin/tee", "/hi"},
		AttachStdout: true,
		AttachStdin:  true,
		Tty:          true,
	})
	if err != nil {
		log.Fatalf("failed to create exec: %v", err)
	}
	log.Printf("Exec created with ID: %v", execResp.ID)

	// 2. Create a string buffer with content "hello, world\n"
	helloBuffer := bytes.NewBufferString("hello, world\n")
	log.Printf("Created string buffer with content: %q", strings.TrimSpace(helloBuffer.String()))

	// 3. Attach to the exec that was just created
	log.Printf("Attaching to exec")
	attachResp, err := cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		log.Fatalf("failed to attach to exec: %v", err)
	}
	defer attachResp.Close()

	// 4. Manipulate the HijackedResponse by writing to it
	log.Printf("Manipulating HijackedResponse")

	go func() {
		io.Copy(os.Stdout, attachResp.Reader)
	}()

	// 5. Pipe the "hello, world\n" string buffer to the exec
	log.Printf("Piping string buffer to exec")
	_, err = io.Copy(attachResp.Conn, helloBuffer)
	if err != nil {
		log.Fatalf("failed to pipe data to exec: %v", err)
	}

	time.Sleep(10 * time.Second)

	// Close the connection to signal end of input
	attachResp.CloseWrite()

	// Print the collected stdout
	log.Printf("Exec completed successfully")

	cli.ContainerStop(ctx, resp.ID, container.StopOptions{})
}
