package models

import (
	"context"
	"fmt"
	"log"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgfrrvtysh "github.com/internetworklab/netapply/pkg/frr/vtysh"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func (nodeConfig *NodeConfig) Up(ctx context.Context) error {
	ctx = pkgutils.SetStatefulDirInCtx(ctx, nodeConfig.StatefulDir)

	if nodeConfig.FRRContainers != nil {
		log.Println("Setting up docker containers ...")
		for _, dockerContainer := range nodeConfig.FRRContainers {
			log.Printf("Setting up %s ...", pkgdocker.GetContainerDisplayName(&dockerContainer.ContainerName))
			if err := dockerContainer.Apply(ctx); err != nil {
				return fmt.Errorf("failed to create container %s: %w", pkgdocker.GetContainerDisplayName(&dockerContainer.ContainerName), err)
			}
		}
	}

	if nodeConfig.Dataplane != nil {
		log.Println("Setting up dataplane ...")
		if err := nodeConfig.Dataplane.Reconcile(ctx, nodeConfig.Containers); err != nil {
			return fmt.Errorf("failed to reconcile dataplane: %w", err)
		}

	}

	if nodeConfig.Controlplane != nil {
		log.Println("Setting up controlplane ...")
		for _, controlPlaneConfig := range nodeConfig.Controlplane {
			log.Printf("Setting up controlplane for %s ...", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName))
			if err := controlPlaneConfig.Apply(ctx); err != nil {
				return fmt.Errorf("failed to create controlplane: %w", err)
			}
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
		openVPNChangeSet.Log()
		changeSet = changeSet.Merge(openVPNChangeSet)
	}

	log.Println("Detecting changes for WireGuard ...")
	wireGuardChangeSet, err := dpConfig.WireGuard.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for WireGuard: %w", err)
	}
	if wireGuardChangeSet != nil && wireGuardChangeSet.HasChanges() {
		log.Println("Found changes for WireGuard dataplane config", *wireGuardChangeSet)
		wireGuardChangeSet.Log()
		changeSet = changeSet.Merge(wireGuardChangeSet)
	}

	log.Println("Detecting changes for VXLAN ...")
	vxlanChangeSet, err := dpConfig.VXLAN.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for VXLAN: %w", err)
	}
	if vxlanChangeSet != nil && vxlanChangeSet.HasChanges() {
		log.Printf("Found changes for VXLAN dataplane config: %v\n", *vxlanChangeSet)
		vxlanChangeSet.Log()
		changeSet = changeSet.Merge(vxlanChangeSet)
	}

	log.Println("Detecting changes for VethPair ...")
	vethPairChangeSet, err := dpConfig.VethPair.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for VethPair: %w", err)
	}
	if vethPairChangeSet != nil && vethPairChangeSet.HasChanges() {
		log.Println("Found changes for VethPair dataplane config", *vethPairChangeSet)
		vethPairChangeSet.Log()
		changeSet = changeSet.Merge(vethPairChangeSet)
	}

	log.Println("Detecting changes for Bridge ...")
	bridgeChangeSet, err := dpConfig.Bridge.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for Bridge: %w", err)
	}
	if bridgeChangeSet != nil && bridgeChangeSet.HasChanges() {
		log.Println("Found changes for Bridge dataplane config", *bridgeChangeSet)
		bridgeChangeSet.Log()
		changeSet = changeSet.Merge(bridgeChangeSet)
	}

	log.Println("Detecting changes for Dummy ...")
	dummyChangeSet, err := dpConfig.Dummy.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for Dummy: %w", err)
	}
	if dummyChangeSet != nil && dummyChangeSet.HasChanges() {
		log.Println("Found changes for Dummy dataplane config", *dummyChangeSet)
		dummyChangeSet.Log()
		changeSet = changeSet.Merge(dummyChangeSet)
	}

	return changeSet, nil
}

func (dpConfig *DataplaneConfig) Reconcile(ctx context.Context, containers []string) error {
	log.Println("Detecting changes for dataplane config ...")
	changeSet, err := dpConfig.DetectChanges(ctx, containers)
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}

	maxLoop := 10
	iterId := 0

	for changeSet != nil && changeSet.HasChanges() && maxLoop > 0 {
		log.Printf("Iteration %d: Found changeset, applying changes for dataplane config ...", iterId)
		changeSet.Log()

		log.Println("Applying changes for dataplane config ...")
		if err := changeSet.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}

		log.Println("Changeset is applied to dataplane config, detecting changes again ...")
		changeSet, err = dpConfig.DetectChanges(ctx, containers)
		if err != nil {
			return fmt.Errorf("failed to detect changes: %w", err)
		}
		maxLoop--
	}

	if maxLoop == 0 && changeSet != nil && changeSet.HasChanges() {
		return fmt.Errorf("failed to reconcile dataplane config, max loop reached")
	}

	return nil
}

func appendExit(cmds []string) []string {
	return append(cmds, "exit")
}

func prependConfigure(cmds []string) []string {
	return append([]string{"configure terminal"}, cmds...)
}

func writeCommands(ctx context.Context, containerName *string, cmds []string) error {
	configWriter, err := pkgfrrvtysh.GetVtyshConfigWriter(ctx, containerName)
	if err != nil {
		return fmt.Errorf("failed to get vtysh config writer: %w", err)
	}
	defer configWriter.Close()
	return configWriter.WriteCommands(ctx, appendExit(prependConfigure(cmds)))

}

func (controlPlaneConfig *ControlplaneConfig) Apply(ctx context.Context) error {

	globalCommands := make([]string, 0)
	if controlPlaneConfig.LogLevel != nil && *controlPlaneConfig.LogLevel != "" {
		globalCommands = append(globalCommands, fmt.Sprintf("log stdout %s", *controlPlaneConfig.LogLevel))
	}
	if controlPlaneConfig.DebugBGPUpdates != nil && *controlPlaneConfig.DebugBGPUpdates {
		globalCommands = append(globalCommands, "debug bgp updates")
	}
	if controlPlaneConfig.DebugOSPFUpdates != nil && *controlPlaneConfig.DebugOSPFUpdates {
		globalCommands = append(globalCommands, "debug ospf updates")
	}
	if controlPlaneConfig.DebugRPKI != nil && *controlPlaneConfig.DebugRPKI {
		globalCommands = append(globalCommands, "debug rpki")
	}
	if controlPlaneConfig.DebugZebraEvents != nil && *controlPlaneConfig.DebugZebraEvents {
		globalCommands = append(globalCommands, "debug zebra events")
	}
	if controlPlaneConfig.DebugZebraDplane != nil && *controlPlaneConfig.DebugZebraDplane {
		globalCommands = append(globalCommands, "debug zebra dplane")
	}
	if controlPlaneConfig.DebugZebraKernel != nil && *controlPlaneConfig.DebugZebraKernel {
		globalCommands = append(globalCommands, "debug zebra kernel")
	}

	if len(globalCommands) > 0 {
		log.Println("Applying global debugging commands ...")
		if err := writeCommands(ctx, controlPlaneConfig.ContainerName, globalCommands); err != nil {
			return fmt.Errorf("failed to write global debugging commands to %s: %w", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName), err)
		}
	}

	if controlPlaneConfig.OSPFv2 != nil {
		log.Println("Applying OSPFv2 configuration ...")
		for _, ospfConfig := range controlPlaneConfig.OSPFv2 {
			log.Printf("Writing OSPFv2 configuration for %s ...", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName))
			if err := writeCommands(ctx, controlPlaneConfig.ContainerName, ospfConfig.ToCLICommands()); err != nil {
				return fmt.Errorf("failed to write OSPFv2 config to %s: %w", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName), err)
			}
		}
	}

	// It's better to enable RPKI before BGP
	if controlPlaneConfig.RPKI != nil {
		log.Println("Applying RPKI configuration ...")
		for _, rpkiConfig := range controlPlaneConfig.RPKI {
			log.Printf("Writing RPKI configuration for %s ...", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName))
			if err := writeCommands(ctx, controlPlaneConfig.ContainerName, rpkiConfig.ToCLICommands()); err != nil {
				return fmt.Errorf("failed to write RPKI config to %s: %w", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName), err)
			}
		}
	}

	if controlPlaneConfig.RouteMap != nil {
		log.Println("Applying RouteMap configuration ...")
		for _, routeMapConfig := range controlPlaneConfig.RouteMap {
			log.Printf("Writing RouteMap configuration for %s ...", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName))
			if err := writeCommands(ctx, controlPlaneConfig.ContainerName, routeMapConfig.ToCLICommands()); err != nil {
				return fmt.Errorf("failed to write RouteMap config to %s: %w", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName), err)
			}
		}
	}

	if controlPlaneConfig.BGP != nil {
		log.Println("Applying BGP configuration ...")
		for _, bgpConfig := range controlPlaneConfig.BGP {
			log.Printf("Writing BGP configuration for %s ...", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName))
			if err := writeCommands(ctx, controlPlaneConfig.ContainerName, bgpConfig.ToCLICommands()); err != nil {
				return fmt.Errorf("failed to write BGP config to %s: %w", pkgdocker.GetContainerDisplayName(controlPlaneConfig.ContainerName), err)
			}
		}
	}

	return nil
}
