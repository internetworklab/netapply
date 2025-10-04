package openvpn2

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgopenvpnstructtag "github.com/internetworklab/netapply/pkg/openvpn2/structtag"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
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
		if ovp.Proto != nil && *ovp.Proto != "" {
			res = append(res, *ovp.Proto)
		}
	}
	return res, nil
}

func (ovpInst *OpenVPN2Instance) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	return nil, nil
}

func (ovpInst *OpenVPN2Instance) GetContainerName() *string {
	return &ovpInst.Name
}

func (ovpInst *OpenVPN2Instance) GetInterfaceName() string {
	return ovpInst.Dev
}

func (ovpInst *OpenVPN2Instance) Update(ctx context.Context) error {
	return nil
}

const labelCategoryDataplane string = "dataplane"
const labelIfaceTypeOpenVPN string = "openvpn"

func (ovpInst *OpenVPN2Instance) Create(ctx context.Context) error {
	servicename, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		// servicename is needed, otherwise the controller won't be able
		// to do the cleanup job later.
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	openvpnExec := "openvpn"
	if ovpInst.ExecutablePath != nil && *ovpInst.ExecutablePath != "" {
		openvpnExec = *ovpInst.ExecutablePath
	}

	cmd := make([]string, 0)
	cmd = append(cmd, openvpnExec)
	cliargs, err := pkgopenvpnstructtag.Marshal(ovpInst)
	if err != nil {
		return fmt.Errorf("failed to marshal openvpn2 instance into CLI arguments: %w", err)
	}
	cmd = append(cmd, cliargs...)

	devPermRWM := "rwm"
	containerConfig := pkgdocker.DockerContainerConfig{
		ContainerName: ovpInst.Name,
		Hostname:      ovpInst.HostName,
		Labels: map[string]string{
			pkgdocker.LabelKeyService:   servicename,
			pkgdocker.LabelKeyInstance:  ovpInst.Name,
			pkgdocker.LabelKeyCategory:  labelCategoryDataplane,
			pkgdocker.LabelKeyIfaceType: labelIfaceTypeOpenVPN,
		},
		Command:    cmd,
		TTY:        ovpInst.TTY,
		OpenStdin:  ovpInst.OpenStdin,
		AutoRemove: ovpInst.AutoRemove,
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
	ovpConfigDir := path.Join(stateDir, "openvpn", "containers", ovpInst.Name)
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
			Source: pkgutils.ResolvePath(ovpInst.HostTLSCertFile),
			Target: "/etc/openvpn/certs/cert.pem",
		},
		{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(ovpInst.HostTLSKeyFile),
			Target: "/etc/openvpn/certs/key.pem",
		},
	}
	if ovpInst.DHPEMFile != nil {
		volumes = append(volumes, pkgdocker.DockerMountConfig{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(*ovpInst.HostDHPEMFile),
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

	cont, err := pkgdocker.FindContainer(ctx, cli, ovpInst.Name)
	if err != nil {
		return false
	}

	if cont == nil {
		return false
	}

	return true
}

// By default, it scans all tun/tap virtual interfaces in the specified containers
func getContainerAndIfaces(ctx context.Context, serviceName string, containerNames []string) (map[string]map[string]pkgreconcile.InterfaceCanceller, error) {
	args := filters.NewArgs()
	args.Add("label", fmt.Sprintf("%s=%s", pkgdocker.LabelKeyService, serviceName))
	args.Add("label", fmt.Sprintf("%s=%s", pkgdocker.LabelKeyCategory, labelCategoryDataplane))
	args.Add("label", fmt.Sprintf("%s=%s", pkgdocker.LabelKeyIfaceType, labelIfaceTypeOpenVPN))

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	conts, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: args,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	scanContNameSet := make(map[string]bool)
	for _, contName := range containerNames {
		scanContNameSet[contName] = true
	}

	result := make(map[string]map[string]pkgreconcile.InterfaceCanceller)
	for _, cont := range conts {
		contName := pkgutils.NormalizeContainerName(cont.Names[0])
		if _, ok := scanContNameSet[contName]; !ok {
			continue
		}

		ifaceMap, err := pkgreconcile.GetInterfaceFromContainer(ctx, &contName, "tun")
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from container: %w", err)
		}
		result[contName] = ifaceMap

		ifaceMap, err = pkgreconcile.GetInterfaceFromContainer(ctx, &contName, "tap")
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from container: %w", err)
		}
		result[contName] = ifaceMap
	}

	return result, nil
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

	// key is the container name, value is the list of interfaces to be added/removed/updated
	addedSet := make(map[string][]pkgreconcile.InterfaceProvisioner)
	removedSet := make(map[string][]pkgreconcile.InterfaceCanceller)
	updatedSet := make(map[string][]pkgreconcile.InterfaceChangeSet)

	specMap := make(map[string]map[string]OpenVPN2Instance)
	for _, c := range ovpList {
		nsKey := string(pkgdocker.GetContainerKey(c.GetContainerName()))
		if _, ok := specMap[nsKey]; !ok {
			specMap[nsKey] = make(map[string]OpenVPN2Instance)
		}
		specMap[nsKey][c.GetInterfaceName()] = c
	}

	currentIfacesMap, err := getContainerAndIfaces(ctx, serviceName, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to get container and ifaces: %w", err)
	}
	log.Println("Debugging openvpn2 current ifaces map: ")
	for nsKey, ifaceMap := range currentIfacesMap {
		for ifaceName := range ifaceMap {
			// Print it out to see what `getContainerAndIfaces` gets
			log.Printf("%s: %s", pkgdocker.GetContainerDisplayName(&nsKey), ifaceName)
		}
	}

	// todo: rewrite this
	for _, nsKey := range containers {
		if ifaceMap, ok := currentIfacesMap[nsKey]; ok && ifaceMap != nil {
			for ifaceName := range ifaceMap {
				if _, ok := specMap[nsKey]; !ok {
					if _, hit := removedSet[nsKey]; !hit {
						removedSet[nsKey] = make([]pkgreconcile.InterfaceCanceller, 0)
					}
					removedSet[nsKey] = append(removedSet[nsKey], &OpenVPN2InterfaceCanceller{ContainerName: nsKey, InterfaceName: ifaceName})
				}
			}
		}

		if specSubMap, ok := specMap[nsKey]; ok && specSubMap != nil {
			for ifaceName, ifspec := range specSubMap {
				if _, ok := currentIfacesMap[nsKey]; !ok {
					if _, hit := addedSet[nsKey]; !hit {
						addedSet[nsKey] = make([]pkgreconcile.InterfaceProvisioner, 0)
					}
					addedSet[nsKey] = append(addedSet[nsKey], &ifspec)
					continue
				}
				if _, ok := currentIfacesMap[nsKey][ifaceName]; !ok {
					if _, hit := removedSet[nsKey]; !hit {
						addedSet[nsKey] = make([]pkgreconcile.InterfaceProvisioner, 0)
					}
					addedSet[nsKey] = append(addedSet[nsKey], &ifspec)
					continue
				}
			}
		}
	}

	log.Println("Debugging openvpn2 changeset:")
	for nsKey, ifaces := range addedSet {
		ifaceList := make([]string, 0)
		for _, ifaceObj := range ifaces {
			ifaceList = append(ifaceList, ifaceObj.GetInterfaceName())
		}
		log.Printf("added: %s: %v", nsKey, strings.Join(ifaceList, ", "))
	}
	for nsKey, ifaces := range removedSet {
		ifaceList := make([]string, 0)
		for _, canceller := range ifaces {
			ifaceList = append(ifaceList, canceller.GetInterfaceName())
		}
		log.Printf("removed: %s: %v", nsKey, strings.Join(ifaceList, ", "))
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
	return ovpInterfaceCanceller.InterfaceName
}
