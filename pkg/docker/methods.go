package docker

import (
	"context"
	"fmt"
	"os"

	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func (dockerConfig *DockerContainerConfig) Create(ctx context.Context) error {
	containerConfig := &container.Config{}
	hostConfig := &container.HostConfig{}
	networkConfig := &network.NetworkingConfig{}
	containerName := dockerConfig.ContainerName
	if containerName == "" {
		return fmt.Errorf("container name is not set")
	}

	dockerConfig.ApplyToContainerCreateConfig(containerConfig, hostConfig, networkConfig)
	containerConfig.Cmd = dockerConfig.Command
	containerConfig.Tty = true
	containerConfig.OpenStdin = true
	servicename, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}
	containerConfig.Labels = map[string]string{
		LabelKeyService: servicename,
	}

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	resp, err := cli.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		networkConfig,
		nil,
		containerName,
	)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

func (dockerConfig *DockerContainerConfig) ApplyToContainerCreateConfig(
	containerConfig *container.Config,
	hostConfig *container.HostConfig,
	networkConfig *network.NetworkingConfig,
) {
	if containerConfig != nil {
		containerConfig.Image = dockerConfig.Image
		containerConfig.Cmd = dockerConfig.Command

		if dockerConfig.Hostname != nil {
			containerConfig.Hostname = *dockerConfig.Hostname
		}
	}

	if networkConfig != nil {
		if dockerConfig.Networks != nil {
			networkConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)
			for _, networkName := range dockerConfig.Networks {
				networkConfig.EndpointsConfig[networkName] = &network.EndpointSettings{}
			}
		}
	}

	if hostConfig != nil {
		if dockerConfig.AutoRemove != nil {
			hostConfig.AutoRemove = *dockerConfig.AutoRemove
		}

		if dockerConfig.Capabilities != nil {
			hostConfig.CapAdd = strslice.StrSlice(dockerConfig.Capabilities)
		}

		if dockerConfig.Ports != nil {
			portMaps := make(nat.PortMap, 0)
			for containerPort, hostPortMappings := range dockerConfig.Ports {
				portbindings := make([]nat.PortBinding, 0)
				for _, hostPortMapping := range hostPortMappings {
					portbindings = append(portbindings, nat.PortBinding{
						HostIP:   hostPortMapping.HostIP,
						HostPort: fmt.Sprintf("%d", hostPortMapping.HostPort),
					})
				}
				portMaps[nat.Port(containerPort)] = portbindings
			}
			hostConfig.PortBindings = portMaps
		}

		if dockerConfig.Volumes != nil {
			volumeMounts := make([]mount.Mount, 0)
			for _, volumeMount := range dockerConfig.Volumes {
				volumeMounts = append(volumeMounts, mount.Mount{
					Type:   volumeMount.Type,
					Source: pkgutils.ResolvePath(volumeMount.Source),
					Target: volumeMount.Target,
				})
			}
			hostConfig.Mounts = volumeMounts
		}

		if dockerConfig.Devices != nil {
			deviceMounts := make([]container.DeviceMapping, 0)
			for _, deviceMount := range dockerConfig.Devices {
				perm := "rwm"
				if deviceMount.CgroupPermissions != nil {
					perm = *deviceMount.CgroupPermissions
				}
				deviceMounts = append(deviceMounts, container.DeviceMapping{
					PathOnHost:        pkgutils.ResolvePath(deviceMount.PathOnHost),
					PathInContainer:   deviceMount.PathInContainer,
					CgroupPermissions: perm,
				})
			}
			hostConfig.Devices = deviceMounts
		}
	}
}

func FindContainer(ctx context.Context, cli *client.Client, containerName string) (*container.Summary, error) {
	filters := filters.NewArgs()
	filters.Add("name", containerName)

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: filters,
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
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker client from context: %w", err)
	}

	cont, err := FindContainer(ctx, cli, containerName)
	if err == nil && cont != nil {
		if cont.State == container.StateRunning {
			if err := cli.ContainerStop(ctx, containerName, container.StopOptions{}); err != nil {
				return fmt.Errorf("failed to stop container: %w", err)
			}
		}
		if err := cli.ContainerRemove(ctx, containerName, container.RemoveOptions{}); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
	}

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

func WithNsHandle(ctx context.Context, containerName *string, f func(h *netlink.Handle) error) error {
	if containerName == nil {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("failed to create netlink handle: %w", err)
		}
		defer handle.Close()
		return f(handle)
	}

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}
	nsHandle, err := GetNetNSHandle(ctx, cli, *containerName)
	if err != nil {
		return fmt.Errorf("failed to get netns from docker: %w", err)
	}
	defer nsHandle.Close()

	handle, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer handle.Close()

	return f(handle)
}

func WithNetnsWGCli(ctx context.Context, containerName *string, hook func(wgCtrlCli *wgctrl.Client) error) error {
	var wgCtrlCli *wgctrl.Client
	var err error

	if containerName != nil {
		cli, err := pkgutils.DockerCliFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get docker client: %s", err.Error())
		}

		nsHandle, err := GetNetNSHandle(ctx, cli, *containerName)
		if err != nil {
			return fmt.Errorf("failed to get netns: %s", err.Error())
		}
		defer nsHandle.Close()

		hostPid := os.Getpid()
		hostNsHandle, err := netns.GetFromPid(hostPid)
		if err != nil {
			return fmt.Errorf("failed to get host netns: %s", err.Error())
		}
		defer hostNsHandle.Close()

		netns.Set(nsHandle)
		defer netns.Set(hostNsHandle)

		wgCtrlCli, err = wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
		}
		defer wgCtrlCli.Close()
	} else {
		wgCtrlCli, err = wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
		}
		defer wgCtrlCli.Close()
	}

	return hook(wgCtrlCli)
}

func GetContainerKey(containerName *string) ContainerKey {
	if containerName == nil {
		return ContainerKeyHost
	}

	if *containerName == "" || *containerName == "-" {
		return ContainerKeyHost
	}

	return ContainerKey(*containerName)
}

func GetContainerDisplayName(containerName *string) string {
	if containerName != nil {
		return fmt.Sprintf("container %s", *containerName)
	}

	return "host"
}

func (containerList *ContainerList) GetContainers() []container.Summary {
	return containerList.containers
}

func NewContainerListFromServiceName(ctx context.Context, serviceName string) (*ContainerList, error) {
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	dockerArgs := filters.NewArgs()
	dockerArgs.Add("label", fmt.Sprintf("%s=%s", LabelKeyService, serviceName))
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: dockerArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return &ContainerList{containers: containers}, nil
}
