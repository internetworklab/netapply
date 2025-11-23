package utils

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/vishvananda/netns"
)

type ContainerKey string

const (
	ContainerKeyHost ContainerKey = "-"
)

// If no container is found, return (nil, nil), by default, it expects exact match
func findContainer(ctx context.Context, cli *client.Client, containerName string) (*container.Summary, error) {
	filters := filters.NewArgs()
	filters.Add("name", "^"+containerName+"$")

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: filters,
		All:     true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		return nil, nil
	}

	return &containers[0], nil
}

func GetNetNSHandle(ctx context.Context, cli *client.Client, containerName string) (netns.NsHandle, error) {
	container, err := findContainer(ctx, cli, containerName)
	if err != nil {
		return -1, fmt.Errorf("failed to find container: %w", err)
	}

	if container == nil {
		return -1, fmt.Errorf("container %s not found", containerName)
	}

	return netns.GetFromDocker(container.ID)
}

func GetContainerNSPid(ctx context.Context, cli *client.Client, containerName string) (*int, error) {
	container, err := findContainer(ctx, cli, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to find container: %w", err)
	}

	if container == nil {
		return nil, fmt.Errorf("container %s not found", containerName)
	}

	resp, err := cli.ContainerInspect(ctx, container.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	return &resp.State.Pid, nil
}
