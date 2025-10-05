package docker

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func (dockerConfig *DockerContainerConfig) ReCreate(ctx context.Context) error {
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	cont, err := FindContainer(ctx, cli, dockerConfig.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}
	if cont == nil {
		return dockerConfig.Create(ctx)
	}

	log.Printf("Deleting container %s", dockerConfig.ContainerName)
	err = StopAndRemoveContainer(ctx, dockerConfig.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to stop and remove container: %w", err)
	}

	log.Printf("Re-creating container %s with desired spec", dockerConfig.ContainerName)
	return dockerConfig.Create(ctx)
}

func (dockerConfig *DockerContainerConfig) Apply(ctx context.Context) error {

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	cont, err := FindContainer(ctx, cli, dockerConfig.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}

	if cont != nil {
		log.Printf("Container %s found: %s\n", GetContainerDisplayName(&dockerConfig.ContainerName), cont.ID)
		switch cont.State {
		case container.StateRunning, container.StateRestarting:
			if checkIfRecreateNeeded(dockerConfig, cont) {
				log.Printf("Container %s is %s, recreating...\n", GetContainerDisplayName(&dockerConfig.ContainerName), cont.State)
				return dockerConfig.ReCreate(ctx)
			}
			log.Printf("Container %s state: %s, skipping...\n", GetContainerDisplayName(&dockerConfig.ContainerName), cont.State)
			return nil
		case container.StateCreated, container.StatePaused:
			log.Printf("Container %s is %s, starting...\n", GetContainerDisplayName(&dockerConfig.ContainerName), cont.State)
			if err := cli.ContainerStart(ctx, cont.ID, container.StartOptions{}); err != nil {
				return fmt.Errorf("failed to start container: %w", err)
			}
		case container.StateExited, container.StateRemoving, container.StateDead:
			return fmt.Errorf("container %s is %s, please try again later", GetContainerDisplayName(&dockerConfig.ContainerName), cont.State)
		default:
			return fmt.Errorf("unknown container state: %s, container %s", cont.State, GetContainerDisplayName(&dockerConfig.ContainerName))
		}
		return nil
	}

	log.Printf("Container %s not found, creating...\n", GetContainerDisplayName(&dockerConfig.ContainerName))
	return dockerConfig.Create(ctx)
}

func pullImageIfNeeded(ctx context.Context, cli *client.Client, img string) error {
	imageList, err := cli.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	imgRepoTag := strings.TrimSpace(img)

	for _, image := range imageList {
		for _, repoTag := range image.RepoTags {
			if repoTag == imgRepoTag {
				log.Printf("Found image %s with id %s", imgRepoTag, image.ID)
				return nil
			}
		}
	}

	reader, err := cli.ImagePull(ctx, imgRepoTag, image.PullOptions{})
	if err != nil {
		panic(err)
	}

	defer reader.Close()

	log.Printf("Pulling image %s", imgRepoTag)

	io.Copy(os.Stdout, reader)

	return nil
}

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

	labels := make(map[string]string)
	if dockerConfig.Labels != nil {
		for k, v := range dockerConfig.Labels {
			labels[k] = v
		}
	}

	servicename, err := pkgutils.ServiceNameFromCtx(ctx)
	if err == nil {
		labels[LabelKeyService] = servicename
	}

	containerConfig.Labels = labels

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	if err := pullImageIfNeeded(ctx, cli, dockerConfig.Image); err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	log.Printf("Creating container %s", containerName)
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

	log.Printf("Starting container %s", containerName)
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

		if dockerConfig.TTY != nil {
			containerConfig.Tty = *dockerConfig.TTY
		}

		if dockerConfig.OpenStdin != nil {
			containerConfig.OpenStdin = *dockerConfig.OpenStdin
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
	cli, err := pkgutils.DockerCliFromCtx(ctx)
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

func WithNsHandle(ctx context.Context, containerName *string, f func(h *netlink.Handle) error) error {
	if containerName == nil || !IsRegularContainerName(*containerName) {
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

func WithNsHandleSafe(ctx context.Context, containerName *string, f func(h *netlink.Handle) error) error {
	if containerName != nil && IsRegularContainerName(*containerName) {
		cli, err := pkgutils.DockerCliFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get docker cli from context: %w", err)
		}

		contSummary, err := FindContainer(ctx, cli, *containerName)
		if err != nil || contSummary == nil {
			// if the container does not exist, simply skip it and reports no error
			return nil
		}
	}
	return WithNsHandle(ctx, containerName, f)
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

func checkDiffSet(lhs, rhs map[string]string) bool {
	for k, v := range lhs {
		if v1, ok := rhs[k]; !ok || v1 != v {
			return true
		}
	}
	return false
}

func checkLabelsMapDiffer(lhs, rhs map[string]string) bool {
	return checkDiffSet(lhs, rhs) || checkDiffSet(rhs, lhs)
}

func portSpecToKeys(spec map[string][]DockerPortMapping) map[string]string {
	keys := make(map[string]string)

	for containerPortAndType, hostPortMappings := range spec {
		for _, hostPortMapping := range hostPortMappings {
			// might looks like 0.0.0.0:8080 -> 8080/tcp
			key := fmt.Sprintf("%s:%d -> %s", hostPortMapping.HostIP, hostPortMapping.HostPort, containerPortAndType)
			keys[key] = containerPortAndType
		}

	}

	return keys
}

func portStatusToKeys(status []container.Port) map[string]string {
	keys := make(map[string]string)

	for _, port := range status {
		key := fmt.Sprintf("%s:%d -> %d/%s", port.IP, port.PublicPort, port.PrivatePort, port.Type)
		keys[key] = fmt.Sprintf("%d/%s", port.PrivatePort, port.Type)
	}

	return keys
}

func checkPortsDiffer(lhs map[string][]DockerPortMapping, rhs []container.Port) bool {
	specKeys := portSpecToKeys(lhs)
	statusKeys := portStatusToKeys(rhs)
	return checkLabelsMapDiffer(specKeys, statusKeys)
}

func checkVolumesDiffer(lhs []DockerMountConfig, rhs []container.MountPoint) bool {

	lhsKeys := make(map[string]string)
	for _, volume := range lhs {
		key := fmt.Sprintf("%s -> %s/%s", volume.Source, volume.Target, volume.Type)
		lhsKeys[key] = volume.Target
	}

	rhsKeys := make(map[string]string)
	for _, volume := range rhs {
		key := fmt.Sprintf("%s -> %s/%s", volume.Source, volume.Destination, volume.Type)
		rhsKeys[key] = volume.Destination
	}

	return checkLabelsMapDiffer(lhsKeys, rhsKeys)
}

func checkIfRecreateNeeded(containerSpec *DockerContainerConfig, containerSummary *container.Summary) bool {
	if containerSpec.Image != containerSummary.Image {
		log.Printf("Container %s image is %s, but expected is %s", containerSummary.Names[0], containerSummary.Image, containerSpec.Image)
		return true
	}

	if checkLabelsMapDiffer(containerSpec.Labels, containerSummary.Labels) {
		log.Printf("Container %s labels are %v, but expected are %v", containerSummary.Names[0], containerSummary.Labels, containerSpec.Labels)
		return true
	}

	if checkPortsDiffer(containerSpec.Ports, containerSummary.Ports) {
		log.Printf("Container %s ports are %v, but expected are %v", containerSummary.Names[0], containerSummary.Ports, containerSpec.Ports)
		return true
	}

	if checkVolumesDiffer(containerSpec.Volumes, containerSummary.Mounts) {
		log.Printf("Container %s volumes are %v, but expected are %v", containerSummary.Names[0], containerSummary.Mounts, containerSpec.Volumes)
		return true
	}

	return false
}

func IsRegularContainerName(containerName string) bool {
	return containerName != "" && containerName != string(ContainerKeyHost)
}
