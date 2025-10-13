package dummy

import (
	"context"
	"fmt"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkginterfacevrf "github.com/internetworklab/netapply/pkg/interface/vrf"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	"github.com/vishvananda/netlink"
)

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetChangedItems() map[string]bool {
	changedItems := make(map[string]bool)
	changedItems["Addresses"] = len(dummyInterfaceChangeSet.AddressesToAdd)+len(dummyInterfaceChangeSet.AddressesToRemove) > 0
	return changedItems
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetContainerName() *string {
	return dummyInterfaceChangeSet.ContainerName
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetInterfaceName() string {
	return dummyInterfaceChangeSet.InterfaceName
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) HasUpdates() bool {
	return len(dummyInterfaceChangeSet.AddressesToRemove)+len(dummyInterfaceChangeSet.AddressesToAdd) > 0
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) Apply(ctx context.Context) error {
	if !dummyInterfaceChangeSet.HasUpdates() {
		return nil
	}

	return pkgdocker.WithNsHandle(ctx, dummyInterfaceChangeSet.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(dummyInterfaceChangeSet.InterfaceName)
		if err == nil && link != nil {

			if dummyInterfaceChangeSet.VRFToSet != nil {
				if err := pkginterfacevrf.TrySetVRF(handle, link, dummyInterfaceChangeSet.VRFToSet); err != nil {
					return fmt.Errorf("failed to set vrf for dummy link: %w", err)
				}
			}

			for _, addr := range dummyInterfaceChangeSet.AddressesToRemove {
				if err := handle.AddrDel(link, addr); err != nil {
					return fmt.Errorf("failed to remove address from dummy link: %w", err)
				}
			}

			for _, addr := range dummyInterfaceChangeSet.AddressesToAdd {
				if err := handle.AddrAdd(link, addr); err != nil {
					return fmt.Errorf("failed to add address to dummy link: %w", err)
				}
			}

		}
		return nil
	})
}

func (dummyConfig *DummyConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	changeSet := new(DummyInterfaceChangeSet)
	for _, addr := range dummyConfig.Addresses {
		nlAddr, err := addr.ToNetlinkAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to netlink addr: %w", err)
		}
		changeSet.AddressesToAdd = append(changeSet.AddressesToAdd, nlAddr)
	}

	pkgdocker.WithNsHandle(ctx, dummyConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(dummyConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get dummy link: %w", err)
		}

		if dummyConfig.VRF != nil {
			diff, err := pkginterfacevrf.CheckVRFDiff(handle, link, dummyConfig.VRF)
			if err != nil {
				return fmt.Errorf("failed to check vrf diff: %w", err)
			}

			changeSet.VRFToSet = diff
		}

		addrsChangeSet, err := pkginterfacecommon.CompareSpecAddrsAgainstActualAddrs(dummyConfig.Addresses, link, handle)
		if err != nil {
			return fmt.Errorf("failed to compare spec addrs against actual addrs: %w", err)
		}
		changeSet.AddressesToAdd = addrsChangeSet.AddressesToAdd
		changeSet.AddressesToRemove = addrsChangeSet.AddressesToRemove

		return nil
	})

	changeSet.ContainerName = dummyConfig.ContainerName
	changeSet.InterfaceName = dummyConfig.Name

	return changeSet, nil
}

func (dummyConfig *DummyConfig) GetContainerName() *string {
	return dummyConfig.ContainerName
}

func (dummyConfig *DummyConfig) GetInterfaceName() string {
	return dummyConfig.Name
}

func (dummyConfig *DummyConfig) Create(ctx context.Context) error {
	return pkgdocker.WithNsHandle(ctx, dummyConfig.ContainerName, func(handle *netlink.Handle) error {
		link := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: dummyConfig.Name,
			},
		}

		err := handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add dummy link: %w", err)
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set up dummy link: %w", err)
		}

		if dummyConfig.VRF != nil {
			if err := pkginterfacevrf.TrySetVRF(handle, link, dummyConfig.VRF); err != nil {
				return fmt.Errorf("failed to set vrf for dummy link: %w", err)
			}
		}

		for _, addr := range dummyConfig.Addresses {
			nlAddr, err := addr.ToNetlinkAddr()
			if err != nil {
				return fmt.Errorf("failed to convert address to netlink addr: %w", err)
			}
			err = handle.AddrAdd(link, nlAddr)
			if err != nil {
				return fmt.Errorf("failed to add address to dummy link: %w", err)
			}
		}

		return nil
	})
}

func (dummyList DummyConfigurationList) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {
	dummyTy := new(netlink.Dummy).Type()
	provisionerList := make([]pkgreconcile.InterfaceProvisioner, 0)
	for _, dummy := range dummyList {
		provisionerList = append(provisionerList, &dummy)
	}
	return pkgreconcile.DetectChanges(ctx, provisionerList, dummyTy, containers)
}

func (dummyConfig *DummyConfig) GetType() string {
	return new(netlink.Dummy).Type()
}

func (dummyConfig *DummyConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, dummyConfig)
}
