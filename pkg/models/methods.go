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

	if nodeConfig.Resources != nil {
		log.Println("Setting up dataplane ...")
		if err := nodeConfig.Resources.Reconcile(ctx); err != nil {
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

func (dpConfig *ResourcesConfig) DetectChanges(ctx context.Context) (*pkgreconcile.ResourceListChangeSet, error) {

	var changeSet *pkgreconcile.ResourceListChangeSet

	reconcileTargets := make([]pkgreconcile.ResourceProvisionersList, 0)
	reconcileTargets = append(reconcileTargets, dpConfig.OpenVPN)
	reconcileTargets = append(reconcileTargets, dpConfig.VRF)
	reconcileTargets = append(reconcileTargets, dpConfig.WireGuard)
	reconcileTargets = append(reconcileTargets, dpConfig.VXLAN)
	reconcileTargets = append(reconcileTargets, dpConfig.VethPair)
	reconcileTargets = append(reconcileTargets, dpConfig.Bridge)
	reconcileTargets = append(reconcileTargets, dpConfig.Dummy)
	reconcileTargets = append(reconcileTargets, dpConfig.Route)

	for _, reconcileTarget := range reconcileTargets {
		if reconcileTarget == nil {
			continue
		}
		log.Println("Detecting changes for", reconcileTarget.GetType(), "...")
		subChangeSet, err := pkgreconcile.DetectChangesForProvisionersList(ctx, reconcileTarget)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes for %s: %w", reconcileTarget.GetType(), err)
		}
		if subChangeSet != nil && subChangeSet.HasChanges() {
			log.Println("Found changes for", reconcileTarget.GetType(), "dataplane config", *subChangeSet)
			changeSet = changeSet.Merge(subChangeSet)
		}
	}

	return changeSet, nil
}

func (dpConfig *ResourcesConfig) Reconcile(ctx context.Context) error {
	log.Println("Detecting changes for dataplane config ...")
	changeSet, err := dpConfig.DetectChanges(ctx)
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
		changeSet, err = dpConfig.DetectChanges(ctx)
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
