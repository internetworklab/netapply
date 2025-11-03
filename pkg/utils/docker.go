package utils

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/vishvananda/netns"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
)

type ContainerKey string

const (
	ContainerKeyHost ContainerKey = "-"
)

// If no container is found, return (nil, nil), by default, it expects exact match
func FindContainer(ctx context.Context, cli *client.Client, containerName string) (*container.Summary, error) {
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

func StopAndRemoveContainer(ctx context.Context, containerName string) error {
	cli, err := DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker client from context: %w", err)
	}

	cont, err := FindContainer(ctx, cli, containerName)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}

	if cont == nil {
		log.Printf("Container %s is already removed, nothing to do", containerName)
		return nil
	}

	log.Printf("Stop and removing container %s, container id: %s, state: %s", containerName, cont.ID, cont.State)
	switch cont.State {
	case container.StateRunning, container.StateRestarting:
		log.Printf("Container %s is running, shutting it down...", containerName)
		if err := cli.ContainerStop(ctx, containerName, container.StopOptions{}); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}

		log.Printf("Waiting for container %s to stop...", containerName)
		respCh, errCh := cli.ContainerWait(ctx, containerName, container.WaitConditionNotRunning)
		var err error
		select {
		case <-respCh:
		case err = <-errCh:
		}

		if err != nil {
			return fmt.Errorf("failed to wait for container to stop: %w", err)
		}

		log.Printf("Container %s stopped", containerName)
	}

	log.Printf("Removing container %s", containerName)
	err = cli.ContainerRemove(ctx, containerName, container.RemoveOptions{Force: true})
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	cont, err = FindContainer(ctx, cli, containerName)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}
	if cont != nil {
		log.Printf("Waiting for container %s to be removed...", containerName)
		respCh, errCh := cli.ContainerWait(ctx, containerName, container.WaitConditionRemoved)
		select {
		case <-respCh:
		case err = <-errCh:
		}
		if err != nil {
			return fmt.Errorf("failed to wait for container to be removed: %w", err)
		}
	}

	log.Printf("Container %s is removed", containerName)

	return nil
}

func GetNetNSHandle(ctx context.Context, cli *client.Client, containerName string) (netns.NsHandle, error) {
	container, err := FindContainer(ctx, cli, containerName)
	if err != nil {
		return -1, fmt.Errorf("failed to find container: %w", err)
	}

	if container == nil {
		return -1, fmt.Errorf("container %s not found", containerName)
	}

	return netns.GetFromDocker(container.ID)
}

func GetContainerNSPid(ctx context.Context, cli *client.Client, containerName string) (*int, error) {
	container, err := FindContainer(ctx, cli, containerName)
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

func GetContainerKey(netnsInfo *pkgnetns.NetNsInfo) ContainerKey {
	if netnsInfo == nil {
		return ContainerKeyHost
	}

	if netnsInfo.Pid == 0 {
		return ContainerKeyHost
	}

	return ContainerKey(strconv.Itoa(netnsInfo.Pid))
}

func GetContainerDisplayName(netnsInfo *pkgnetns.NetNsInfo) string {
	if netnsInfo == nil {
		return "host"
	}

	return fmt.Sprintf("pid %d", netnsInfo.Pid)
}
