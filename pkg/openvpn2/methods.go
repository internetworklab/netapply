package openvpn2

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	pkgdocker "example.com/connector/pkg/docker"
	pkgreconcile "example.com/connector/pkg/reconcile"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/api/types/mount"
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
	return &ovpInst.ContainerName
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
		// servicename is needed, otherwise the controller won't be able
		// to do the cleanup job later.
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	tty := true
	openStdin := true
	autoRemove := true
	devPermRWM := "rwm"
	containerConfig := pkgdocker.DockerContainerConfig{
		ContainerName: ovpInst.ContainerName,
		Hostname:      ovpInst.HostName,
		Labels: map[string]string{
			pkgdocker.LabelKeyService:  servicename,
			pkgdocker.LabelKeyInstance: ovpInst.Name,
		},
		TTY:        &tty,
		OpenStdin:  &openStdin,
		AutoRemove: &autoRemove,
		Networks:   ovpInst.DockerNetworks,
		Image:      ovpInst.Image,
		Capabilities: []string{
			"net_admin",
			"sys_admin",
		},
		Ports: ovpInst.Ports,
		Devices: []pkgdocker.DockerDeviceMapping{
			{
				PathOnHost:        "/dev/net/tun",
				PathInContainer:   "/dev/net/tun",
				CgroupPermissions: &devPermRWM,
			},
		},
	}
	stateDir := pkgutils.GetStatefulDir(ctx)
	ovpConfigDir := path.Join(stateDir, "openvpn")
	err = os.MkdirAll(ovpConfigDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create openvpn config dir: %w", err)
		}
	}
	ovpScriptDir := path.Join(ovpConfigDir, "scripts")
	err = os.MkdirAll(ovpScriptDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create openvpn script dir: %w", err)
		}
	}
	upWrapperScriptPath := path.Join(ovpScriptDir, "up-wrapper.sh")

	scriptContent := []byte(strings.Join([]string{
		"#!/bin/bash",
		"",
		"echo \"Setting up $1\"",
		"ip link set $1 up",
		"",
	}, "\n"))

	// Repetitive write will simply override the previous content,
	// so nothing to worry about.
	if err := os.WriteFile(upWrapperScriptPath, scriptContent, 0755); err != nil {
		return fmt.Errorf("failed to write up-wrapper script: %w", err)
	}

	volumes := []pkgdocker.DockerMountConfig{
		{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(upWrapperScriptPath),
			Target: "/up-wrapper.sh",
		},
		{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(ovpInst.CertFile),
			Target: "/etc/openvpn/certs/cert.pem",
		},
		{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(ovpInst.KeyFile),
			Target: "/etc/openvpn/certs/key.pem",
		},
	}
	if ovpInst.DHPEMFile != nil {
		volumes = append(volumes, pkgdocker.DockerMountConfig{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(*ovpInst.DHPEMFile),
			Target: "/etc/openvpn/certs/dh.pem",
		})
	}

	containerConfig.Volumes = volumes
	return containerConfig.Apply(ctx)
}

func (ovpInst *OpenVPN2Instance) IsLinkExists(ctx context.Context) bool {
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		panic(err)
	}

	cont, err := pkgdocker.FindContainer(ctx, cli, ovpInst.ContainerName)
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
		specMap[c.ContainerName] = c
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
		if _, ok := containersMap[c.ContainerName]; !ok {
			addedSet[c.ContainerName] = make([]pkgreconcile.InterfaceProvisioner, 0)
			addedSet[c.ContainerName] = append(addedSet[c.ContainerName], &c)
		}
	}

	changeSet.AddedInterfaces = addedSet
	changeSet.RemovedInterfaces = removedSet
	changeSet.UpdatedInterfaces = updatedSet

	return changeSet, nil
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) Cancel(ctx context.Context) error {
	return pkgdocker.StopAndRemoveContainer(ctx, ovpInterfaceCanceller.ContainerName)
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetContainerName() *string {
	return &ovpInterfaceCanceller.ContainerName
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetInterfaceName() string {
	return "-"
}
