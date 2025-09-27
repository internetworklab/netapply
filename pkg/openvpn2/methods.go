package openvpn2

import (
	"context"
	"fmt"

	pkgdocker "example.com/connector/pkg/docker"
	pkgreconcile "example.com/connector/pkg/reconcile"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
)

func (ovp *OpenVPN2RemoteTLSCertType) ToCLIArgs() ([]string, error) {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%v", *ovp))
	}
	return res, nil
}

func (ovp *OpenVPN2KeepaliveConfig) ToCLIArgs() ([]string, error) {

	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%d", ovp.IntervalSecs))
		res = append(res, fmt.Sprintf("%d", ovp.PatienceSecs))
	}
	return res, nil
}

func (ovp *OpenVPN2RemoteConfig) ToCLIArgs() ([]string, error) {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, ovp.Host)
		res = append(res, fmt.Sprintf("%d", ovp.Port))
	}
	return res, nil
}

func (ovpInst *OpenVPN2Instance) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	return nil, nil
}

func (ovpInst *OpenVPN2Instance) GetContainerName() *string {
	return &ovpInst.DockerContainer.ContainerName
}

func (ovpInst *OpenVPN2Instance) GetInterfaceName() string {
	return ovpInst.Dev
}

func (ovpInst *OpenVPN2Instance) Update(ctx context.Context) error {
	return nil
}

func getContainerName(service string, instance string) string {
	return fmt.Sprintf("%s-%s", service, instance)
}

func (ovpInst *OpenVPN2Instance) Create(ctx context.Context) error {
	servicename, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	if ovpInst.DockerContainer == nil {
		return fmt.Errorf("docker container config is not set, currently only support to run in docker container")
	}

	cmd := make([]string, 0)
	exec := "openvpn"
	if ovpInst.ExecutablePath != nil && *ovpInst.ExecutablePath != "" {
		exec = *ovpInst.ExecutablePath
	}
	cmd = append(cmd, exec)

	openvpn2CLIArgs, err := Marshal(ovpInst)
	if err != nil {
		return fmt.Errorf("failed to marshal openvpn2 instance into CLI arguments: %w", err)
	}

	cmd = append(cmd, openvpn2CLIArgs...)

	containerConfig := &container.Config{}
	networkConfig := &network.NetworkingConfig{}
	hostConfig := &container.HostConfig{}

	ovpInst.DockerContainer.ApplyToContainerCreateConfig(containerConfig, hostConfig, networkConfig)
	containerConfig.Cmd = cmd
	containerConfig.Tty = true
	containerConfig.OpenStdin = true
	containerConfig.Labels = map[string]string{
		pkgdocker.LabelKeyService:  servicename,
		pkgdocker.LabelKeyInstance: ovpInst.Name,
	}

	containerName := ovpInst.DockerContainer.ContainerName
	if containerName == "" {
		containerName = getContainerName(servicename, ovpInst.Name)
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

func (ovpInst *OpenVPN2Instance) IsLinkExists(ctx context.Context) bool {
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		panic(err)
	}

	cont, err := pkgdocker.FindContainer(ctx, cli, ovpInst.DockerContainer.ContainerName)
	if err != nil {
		return false
	}

	if cont == nil {
		return false
	}

	return true
}

func (ovpList OpenVPN2ConfigurationList) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {
	// Reconciliaton of container-based OpenVPN instances is quite simple, rules:
	// 1. If the container is present on the system but not in the list, remove it.
	// 2. If the container is not present on the system but in the list, create it.
	// 3. If the container is present both on the system and the list, by optimistic assumption, it doesn't need to be updated.
	// 4. The key is the container name, forget about the interface name.

	changeSet := new(pkgreconcile.DataplaneChangeSet)

	serviceName, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get service name: %w", err)
	}

	containerList, err := pkgdocker.NewContainerListFromServiceName(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get container list from service name: %w", err)
	}

	addedSet := make(map[string][]pkgreconcile.InterfaceProvisioner)
	removedSet := make(map[string][]pkgreconcile.InterfaceCanceller)
	updatedSet := make(map[string][]pkgreconcile.InterfaceChangeSet)

	specMap := make(map[string]OpenVPN2Instance)
	for _, c := range ovpList {
		specMap[c.DockerContainer.ContainerName] = c
	}

	containersMap := make(map[string]interface{})
	for _, container := range containerList.GetContainers() {
		containersMap[container.Names[0]] = container
		if _, ok := specMap[container.Names[0]]; !ok {
			removedSet[container.Names[0]] = make([]pkgreconcile.InterfaceCanceller, 0)
			removedSet[container.Names[0]] = append(removedSet[container.Names[0]], &OpenVPN2InterfaceCanceller{ContainerName: container.Names[0]})
		}
	}

	for _, c := range specMap {
		if _, ok := containersMap[c.DockerContainer.ContainerName]; !ok {
			addedSet[c.DockerContainer.ContainerName] = make([]pkgreconcile.InterfaceProvisioner, 0)
			addedSet[c.DockerContainer.ContainerName] = append(addedSet[c.DockerContainer.ContainerName], &c)
		}
	}

	changeSet.AddedInterfaces = addedSet
	changeSet.RemovedInterfaces = removedSet
	changeSet.UpdatedInterfaces = updatedSet

	return changeSet, nil
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) Cancel(ctx context.Context) error {
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker client: %w", err)
	}

	if err := cli.ContainerStop(ctx, ovpInterfaceCanceller.ContainerName, container.StopOptions{}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetContainerName() *string {
	return &ovpInterfaceCanceller.ContainerName
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetInterfaceName() string {
	return "-"
}
