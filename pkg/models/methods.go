package models

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"

	pkgdocker "example.com/connector/pkg/docker"
	pkgreconcile "example.com/connector/pkg/reconcile"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/api/types/container"
)

func (nodeConfig *NodeConfig) Up(ctx context.Context) error {
	if nodeConfig.DockerContainers != nil {
		log.Println("Setting up docker containers ...")

		for _, dockerContainer := range nodeConfig.DockerContainers {
			log.Printf("Setting up docker container %s ...", dockerContainer.ContainerName)

			if err := dockerContainer.Create(ctx); err != nil {
				return fmt.Errorf("failed to create docker container %s: %w", dockerContainer.ContainerName, err)
			}
		}
	}

	if nodeConfig.Dataplane != nil {
		log.Println("Setting up dataplane ...")
		if err := nodeConfig.Dataplane.Apply(ctx, nodeConfig.Containers); err != nil {
			return fmt.Errorf("failed to create dataplane: %w", err)
		}
	}

	if nodeConfig.Controlplane != nil {
		log.Println("Setting up controlplane ...")
		if err := nodeConfig.Controlplane.Create(ctx); err != nil {
			return fmt.Errorf("failed to create controlplane: %w", err)
		}
	}

	return nil
}

func (dpConfig *DataplaneConfig) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {

	var changeSet *pkgreconcile.DataplaneChangeSet

	log.Println("Detecting changes for OpenVPN ...")
	openVPNChangeSet, err := dpConfig.OpenVPN.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for OpenVPN: %w", err)
	}
	if openVPNChangeSet != nil && openVPNChangeSet.HasChanges() {
		log.Println("Found changes for OpenVPN dataplane config", *openVPNChangeSet)
		changeSet = changeSet.Merge(openVPNChangeSet)
	}

	log.Println("Detecting changes for WireGuard ...")
	wireGuardChangeSet, err := dpConfig.WireGuard.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for WireGuard: %w", err)
	}
	if wireGuardChangeSet != nil && wireGuardChangeSet.HasChanges() {
		log.Println("Found changes for WireGuard dataplane config", *wireGuardChangeSet)
		changeSet = changeSet.Merge(wireGuardChangeSet)
	}

	log.Println("Detecting changes for VXLAN ...")
	vxlanChangeSet, err := dpConfig.VXLAN.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for VXLAN: %w", err)
	}
	if vxlanChangeSet != nil && vxlanChangeSet.HasChanges() {
		log.Printf("Found changes for VXLAN dataplane config: %v\n", *vxlanChangeSet)
		changeSet = changeSet.Merge(vxlanChangeSet)
	}

	log.Println("Detecting changes for VethPair ...")
	vethPairChangeSet, err := dpConfig.VethPair.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for VethPair: %w", err)
	}
	if vethPairChangeSet != nil && vethPairChangeSet.HasChanges() {
		log.Println("Found changes for VethPair dataplane config", *vethPairChangeSet)
		changeSet = changeSet.Merge(vethPairChangeSet)
	}

	log.Println("Detecting changes for Bridge ...")
	bridgeChangeSet, err := dpConfig.Bridge.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for Bridge: %w", err)
	}
	if bridgeChangeSet != nil && bridgeChangeSet.HasChanges() {
		log.Println("Found changes for Bridge dataplane config", *bridgeChangeSet)
		changeSet = changeSet.Merge(bridgeChangeSet)
	}

	log.Println("Detecting changes for Dummy ...")
	dummyChangeSet, err := dpConfig.Dummy.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for Dummy: %w", err)
	}
	if dummyChangeSet != nil && dummyChangeSet.HasChanges() {
		log.Println("Found changes for Dummy dataplane config", *dummyChangeSet)
		changeSet = changeSet.Merge(dummyChangeSet)
	}

	return changeSet, nil
}

func (dpConfig *DataplaneConfig) Apply(ctx context.Context, containers []string) error {
	log.Println("Detecting changes for dataplane config ...")
	changeSet, err := dpConfig.DetectChanges(ctx, containers)
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}
	if changeSet.HasChanges() {
		log.Println("Applying changes for dataplane config ...")
		if err := changeSet.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}
	}

	return nil
}

func (controlPlaneConfig *ControlplaneConfig) Create(ctx context.Context) error {

	configsToApply := make([]string, 0)

	if controlPlaneConfig.OSPF != nil {
		ospfPatchPath := path.Join(controlPlaneConfig.HostPatchDir, "ospf.conf")
		ospfPatchFile, err := os.OpenFile(ospfPatchPath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open ospf patch file: %w", err)
		}
		defer ospfPatchFile.Close()

		for _, ospfConf := range controlPlaneConfig.OSPF {
			cmds := ospfConf.ToCLICommands()
			for _, cmd := range cmds {
				ospfPatchFile.WriteString(cmd + "\n")
			}
		}
		configsToApply = append(configsToApply, path.Join(controlPlaneConfig.ContainerPatchDir, path.Base(ospfPatchPath)))
	}

	if controlPlaneConfig.BGP != nil {
		bgpPatchPath := path.Join(controlPlaneConfig.HostPatchDir, "bgp.conf")
		bgpPatchFile, err := os.OpenFile(bgpPatchPath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %w", err)
		}
		defer bgpPatchFile.Close()

		for _, bgpConf := range controlPlaneConfig.BGP {
			cmds := bgpConf.ToCLICommands()
			for _, cmd := range cmds {
				bgpPatchFile.WriteString(cmd + "\n")
			}
		}
		configsToApply = append(configsToApply, path.Join(controlPlaneConfig.ContainerPatchDir, path.Base(bgpPatchPath)))
	}

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}
	cont, err := pkgdocker.FindContainer(ctx, cli, *controlPlaneConfig.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}
	if cont == nil {
		return fmt.Errorf("container %s not found", *controlPlaneConfig.ContainerName)
	}

	if err := cli.ContainerStart(ctx, cont.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	for _, configToApply := range configsToApply {
		execOptions := container.ExecOptions{
			Cmd: []string{
				"vtysh",
				"-f",
				configToApply,
			},
		}
		exec, err := cli.ContainerExecCreate(ctx, cont.ID, execOptions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create exec: %v\n", err)
			continue
		}

		if err := cli.ContainerExecStart(ctx, exec.ID, container.ExecStartOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start exec: %v\n", err)
			continue
		}
	}

	return nil
}
