package bridge

import (
	"context"
	"fmt"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkginterfacevrf "github.com/internetworklab/netapply/pkg/interface/vrf"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

func (bridgeChangeSet *BridgeInterfaceChangeSet) GetChangedItems() map[string]bool {
	changedItems := make(map[string]bool)
	changedItems["SlaveInterfaces"] = len(bridgeChangeSet.InterfaceToEnslave)+len(bridgeChangeSet.InterfaceToUnslave) > 0
	changedItems["Addresses"] = len(bridgeChangeSet.AddressesToAdd)+len(bridgeChangeSet.AddressesToRemove) > 0
	return changedItems
}

func (bridgeChangeSet *BridgeInterfaceChangeSet) Apply(ctx context.Context) error {
	return pkgdocker.WithNsHandleSafe(ctx, bridgeChangeSet.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeChangeSet.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get bridge link: %w", err)
		}

		if bridgeChangeSet.VRFToSet != nil {
			if err := pkginterfacevrf.TrySetVRF(handle, link, bridgeChangeSet.VRFToSet); err != nil {
				return fmt.Errorf("failed to set vrf for bridge link: %w", err)
			}
		}

		for slaveInterface := range bridgeChangeSet.InterfaceToUnslave {
			lk, err := handle.LinkByName(slaveInterface)
			if err == nil && lk != nil {
				if err := handle.LinkSetNoMaster(lk); err != nil {
					return fmt.Errorf("failed to set slave link no master: %w", err)
				}
			}
		}

		for slaveInterface := range bridgeChangeSet.InterfaceToEnslave {
			lk, err := handle.LinkByName(slaveInterface)
			if err == nil && lk != nil {
				if err := handle.LinkSetMaster(lk, link); err != nil {
					return fmt.Errorf("failed to set slave link master: %w", err)
				}
			}
		}

		return nil
	})
}

func (bridgeChangeSet *BridgeInterfaceChangeSet) GetContainerName() *string {
	return bridgeChangeSet.ContainerName
}

func (bridgeChangeSet *BridgeInterfaceChangeSet) GetInterfaceName() string {
	return bridgeChangeSet.InterfaceName
}

func (bridgeChangeSet *BridgeInterfaceChangeSet) HasUpdates() bool {
	return bridgeChangeSet != nil && (len(bridgeChangeSet.InterfaceToEnslave)+len(bridgeChangeSet.InterfaceToUnslave) > 0 ||
		bridgeChangeSet.VRFToSet != nil)
}

func (bridgeConfig *BridgeConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	changeSet := new(BridgeInterfaceChangeSet)
	changeSet.ContainerName = bridgeConfig.ContainerName
	changeSet.InterfaceName = bridgeConfig.Name
	changeSet.InterfaceToEnslave = make(map[string]interface{})
	changeSet.InterfaceToUnslave = make(map[string]interface{})

	// Since here we use 'WithNsHandleSafe' instead of 'WithNsHandle',
	// the result might be incorrect if the container is not yet running
	// during the detection process.
	err := pkgdocker.WithNsHandleSafe(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get bridge link: %w", err)
		}

		if bridgeConfig.VRF != nil {
			diff, err := pkginterfacevrf.CheckVRFDiff(handle, link, bridgeConfig.VRF)
			if err != nil {
				return fmt.Errorf("failed to check vrf diff: %w", err)
			}
			changeSet.VRFToSet = diff
		}

		enslavedLinks, err := getEnslavedLinks(handle, link)
		if err != nil {
			return fmt.Errorf("failed to get enslaved links: %w", err)
		}

		specSlaveIfs := make(map[string]interface{})
		for _, slaveInterface := range bridgeConfig.SlaveInterfaces {
			specSlaveIfs[slaveInterface] = true
			if _, ok := enslavedLinks[slaveInterface]; !ok {
				changeSet.InterfaceToEnslave[slaveInterface] = true
			}
		}

		for _, slif := range enslavedLinks {
			if _, ok := specSlaveIfs[slif.Attrs().Name]; !ok {
				changeSet.InterfaceToUnslave[slif.Attrs().Name] = true
			}
		}

		addrsChangeSet, err := pkginterfacecommon.CompareSpecAddrsAgainstActualAddrs(bridgeConfig.Addresses, link, handle)
		if err != nil {
			return fmt.Errorf("failed to compare spec addrs against actual addrs: %w", err)
		}
		changeSet.AddressesToAdd = addrsChangeSet.AddressesToAdd
		changeSet.AddressesToRemove = addrsChangeSet.AddressesToRemove

		return nil
	})

	return changeSet, err
}

func (bridgeConfig *BridgeConfig) GetContainerName() *string {
	return bridgeConfig.ContainerName
}

func (bridgeConfig *BridgeConfig) GetInterfaceName() string {
	return bridgeConfig.Name
}

func getEnslavedLinks(handle *netlink.Handle, master netlink.Link) (map[string]netlink.Link, error) {
	allNLLinks, err := handle.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to get all netlink links: %s", err.Error())
	}

	enslavedNLLinks := make(map[string]netlink.Link)
	for _, lk := range allNLLinks {
		if lk.Attrs().MasterIndex == master.Attrs().Index {
			enslavedNLLinks[lk.Attrs().Name] = lk
		}
	}

	return enslavedNLLinks, nil
}

func (bridgeConfig *BridgeConfig) ReconcileEnclaves(ctx context.Context) (map[string]interface{}, map[string]interface{}, error) {
	var added map[string]interface{}
	var removed map[string]interface{}
	actuallyAdded := make(map[string]interface{})
	actuallyRemoved := make(map[string]interface{})

	err := pkgdocker.WithNsHandleSafe(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get bridge link: %w", err)
		}

		specSlaveIfs := make(map[string]interface{})
		for _, slaveInterface := range bridgeConfig.SlaveInterfaces {
			specSlaveIfs[slaveInterface] = slaveInterface
		}

		slaveLinks, err := getEnslavedLinks(handle, link)
		if err != nil {
			return fmt.Errorf("failed to get enslaved links: %w", err)
		}
		slaveLinksMap := make(map[string]interface{})
		for _, slaveLink := range slaveLinks {
			slaveLinksMap[slaveLink.Attrs().Name] = slaveLink
		}

		added, removed = pkgutils.DiffSets(specSlaveIfs, slaveLinksMap)
		for removeSlaveIfName := range removed {
			l, err := handle.LinkByName(removeSlaveIfName)
			if err == nil && l != nil {
				if err := netlink.LinkSetNoMaster(l); err != nil {
					return fmt.Errorf("failed to set slave link no master: %w", err)
				}
				actuallyRemoved[removeSlaveIfName] = removeSlaveIfName
			}
		}

		for addedSlaveIfName := range added {
			lk, err := handle.LinkByName(addedSlaveIfName)
			if err == nil && lk != nil {
				if err := handle.LinkSetMaster(lk, link); err != nil {
					return fmt.Errorf("failed to set slave link master: %w", err)
				}
				actuallyAdded[addedSlaveIfName] = addedSlaveIfName
			}
		}

		return nil
	})

	return actuallyAdded, actuallyRemoved, err
}

func (bridgeConfig *BridgeConfig) Create(ctx context.Context) error {
	return pkgdocker.WithNsHandleSafe(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link := &netlink.Bridge{
			LinkAttrs: netlink.LinkAttrs{
				Name: bridgeConfig.Name,
			},
		}

		err := handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add bridge link: %w", err)
		}

		if bridgeConfig.VRF != nil && *bridgeConfig.VRF != pkginterfacevrf.VRFNameDefault && *bridgeConfig.VRF != pkginterfacevrf.VRFNameEmpty {
			if err := pkginterfacevrf.TrySetVRF(handle, link, bridgeConfig.VRF); err != nil {
				return fmt.Errorf("failed to set vrf for bridge link: %w", err)
			}
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set bridge link up: %w", err)
		}

		for _, addr := range bridgeConfig.Addresses {
			nlAddr, err := addr.ToNetlinkAddr()
			if err != nil {
				return fmt.Errorf("failed to convert address to netlink addr: %w", err)
			}
			err = handle.AddrAdd(link, nlAddr)
			if err != nil {
				return fmt.Errorf("failed to add address to bridge link: %w", err)
			}
		}

		_, _, err = bridgeConfig.ReconcileEnclaves(ctx)
		return err
	})
}

func (bridgeCfgsList *BridgeConfigurationList) GetType() string {
	return new(netlink.Bridge).Type()
}

func (bridgeCfgsList *BridgeConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	if bridgeCfgsList == nil {
		return nil
	}

	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, bridgeCfg := range bridgeCfgsList.Bridges {
		if bridgeCfg.IsSoftDeleted() {
			continue
		}

		provisioners = append(provisioners, &bridgeCfg)
	}
	return provisioners
}

func (bridgeCfgsList *BridgeConfigurationList) IndexCurrentResources(ctx context.Context) (map[string]map[string]pkgreconcile.ResourceCanceller, error) {
	if bridgeCfgsList == nil {
		return nil, nil
	}
	return pkgreconcile.IndexStubNetlinkInterfaceList(ctx, bridgeCfgsList)
}

func (bridgeCfgsList *BridgeConfigurationList) GetContainers() []string {
	if bridgeCfgsList == nil {
		return nil
	}
	return bridgeCfgsList.Containers
}

func (bridgeCfgsList *BridgeConfigurationList) CheckResourceExistInSpec(ctx context.Context, specsMap map[string]map[string]pkgreconcile.ResourceProvisioner, resource pkgreconcile.ResourceCanceller) (bool, error) {
	if bridgeCfgsList == nil {
		return false, nil
	}
	return pkgreconcile.CheckResourceExistInSpec(ctx, specsMap, resource)
}

func (bridgeConfig *BridgeConfig) TrySetup(ctx context.Context) error {
	return pkgdocker.WithNsHandleSafe(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeConfig.Name)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return fmt.Errorf("failed to get bridge link: %w", err)
			}
			return bridgeConfig.Create(ctx)
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set bridge link up: %w", err)
		}

		changeSet, err := bridgeConfig.DetectChanges(ctx)
		if err != nil {
			return fmt.Errorf("failed to detect changes: %w", err)
		}
		if changeSet.HasUpdates() {
			return changeSet.Apply(ctx)
		}

		return nil
	})
}

func (bridgeConfig *BridgeConfig) GetType() string {
	return new(netlink.Bridge).Type()
}

func (bridgeConfig *BridgeConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, bridgeConfig)
}

func (bridgeChangeSet *BridgeInterfaceChangeSet) GetType() string {
	return new(netlink.Bridge).Type()
}

func (bridgeCfgsList *BridgeConfigurationList) DetectChanges(ctx context.Context, delete bool) (*pkgreconcile.ResourceListChangeSet, error) {
	return pkgreconcile.DetectChangesForProvisionersList(ctx, bridgeCfgsList, delete)
}

func (bridgeConfig *BridgeConfig) IsSoftDeleted() bool {
	return bridgeConfig.Deleted
}
