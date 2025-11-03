package dummy

import (
	"context"
	"fmt"

	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkginterfacevrf "github.com/internetworklab/netapply/pkg/interface/vrf"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	"github.com/vishvananda/netlink"
)

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetContainerName() *string {
	return dummyInterfaceChangeSet.ContainerName
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetInterfaceName() string {
	return dummyInterfaceChangeSet.InterfaceName
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) HasUpdates() bool {
	if dummyInterfaceChangeSet == nil {
		return false
	}

	return len(dummyInterfaceChangeSet.AddressesToRemove)+len(dummyInterfaceChangeSet.AddressesToAdd) > 0 || dummyInterfaceChangeSet.VRFToSet != nil
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) Apply(ctx context.Context) error {
	if !dummyInterfaceChangeSet.HasUpdates() {
		return nil
	}

	netnsInfo, err := dummyInterfaceChangeSet.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandle(ctx, netnsInfo, func(handle *netlink.Handle) error {
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
	if err != nil {
		return fmt.Errorf("failed to apply dummy interface change set: %w", err)
	}

	return nil
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
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

	netnsInfo, err := dummyConfig.GetNetNsInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get primary netns info: %w", err)
	}

	err = pkgnetns.WithNsHandle(ctx, netnsInfo, func(handle *netlink.Handle) error {
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

	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for dummy config: %w", err)
	}

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
	netnsInfo, err := dummyConfig.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get primary netns info: %w", err)
	}

	err = pkgnetns.WithNsHandle(ctx, netnsInfo, func(handle *netlink.Handle) error {
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
	if err != nil {
		return fmt.Errorf("failed to create dummy link: %w", err)
	}

	return nil
}

func (dummyCfgsList *DummyConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	if dummyCfgsList == nil {
		return nil
	}
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, dummyCfg := range dummyCfgsList.Dummies {
		if dummyCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &dummyCfg)
	}
	return provisioners
}

func (dummyCfgsList *DummyConfigurationList) GetType() string {
	return new(netlink.Dummy).Type()
}

func (dummyConfig *DummyConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}

func (dummyConfig *DummyConfig) GetType() string {
	return new(netlink.Dummy).Type()
}

func (dummyConfig *DummyConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, dummyConfig)
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetType() string {
	return new(netlink.Dummy).Type()
}

func (dummyCfgsList *DummyConfigurationList) DetectChanges(ctx context.Context, delete bool) (*pkgreconcile.ResourceListChangeSet, error) {
	// todo
	return nil, nil
}

func (dummyConfig *DummyConfig) IsSoftDeleted() bool {
	return dummyConfig.Deleted
}
