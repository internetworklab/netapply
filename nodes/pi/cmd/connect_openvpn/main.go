package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

type Instance struct {
	Name   string
	Target string
}

func getContainerName(service string, instance string) string {
	return fmt.Sprintf("%s-%s", service, instance)
}

const servicename string = "ping"

func startPing(cli *client.Client, instance *Instance, imagename string) error {
	ctx := context.Background()
	instancename := instance.Name
	containername := getContainerName(servicename, instancename)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:     imagename,
		Cmd:       []string{"ping", instance.Target},
		Tty:       true,
		OpenStdin: true,
		Labels:    map[string]string{"service": "ping"},
	}, &container.HostConfig{
		AutoRemove: true,
	}, nil, nil, containername)
	if err != nil {
		return fmt.Errorf("failed to create container for %s: %w", instance.Name, err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container for %s: %w", instance.Name, err)
	}

	return nil
}

func up(servicename string, cli *client.Client) {
	imgname := "busybox:latest"
	pingInstances := []Instance{
		{Name: "loopback", Target: "127.0.0.1"},
		{Name: "loopback6", Target: "::1"},
		{Name: "alidns1", Target: "223.5.5.5"},
		{Name: "alidns2", Target: "223.6.6.6"},
	}
	ctx := context.Background()
	log.Println("Pulling image", imgname)
	reader, err := cli.ImagePull(ctx, imgname, image.PullOptions{})
	if err != nil {
		panic(err)
	}

	defer reader.Close()

	// cli.ImagePull is asynchronous.
	// The reader needs to be read completely for the pull operation to complete.
	// If stdout is not required, consider using io.Discard instead of os.Stdout.
	io.Copy(os.Stdout, reader)

	log.Printf("Starting %s containers", servicename)
	for _, instance := range pingInstances {
		if err := startPing(cli, &instance, imgname); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start ping for %s: %v\n", instance.Name, err)
		}
		log.Println("Container is started for", instance.Name)
	}
}

func down(servicename string, cli *client.Client) {
	dockerArgs := filters.NewArgs()
	dockerArgs.Add("label", fmt.Sprintf("service=%s", servicename))
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{
		Filters: dockerArgs,
	})
	if err != nil {
		panic(err)
	}

	for _, cont := range containers {
		if err := cli.ContainerStop(context.Background(), cont.ID, container.StopOptions{}); err != nil {
			panic(err)
		}
		log.Printf("Container %s is stopped", cont.Names[0])
	}
}

func main() {
	if len(os.Args) > 1 {
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}
		defer cli.Close()

		command := os.Args[1]
		switch command {
		case "up":
			up(servicename, cli)
		case "down":
			down(servicename, cli)
		default:
			panic("command in os.Args[1] is unknown")
		}
	} else {
		panic("command in os.Args[1] is required")
	}
}
