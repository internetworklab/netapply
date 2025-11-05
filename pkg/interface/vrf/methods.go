package vrf

import (
	"context"
	"fmt"
	"net"

	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	"github.com/vishvananda/netlink"
)

func (vrfConfig *VRFConfig) GetInterfaceName() string {
	return vrfConfig.Name
}

func (vrfConfig *VRFConfig) GetType() string {
	return new(netlink.Vrf).Type()
}

func (vrfConfig *VRFConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, vrfConfig)
}

func (vrfConfig *VRFConfig) Create(ctx context.Context) error {
	netnsInfo, err := vrfConfig.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	return pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		link := &netlink.Vrf{
			LinkAttrs: netlink.LinkAttrs{
				Name: vrfConfig.Name,
			},
			Table: vrfConfig.TableId,
		}

		if err := handle.LinkAdd(link); err != nil {
			return fmt.Errorf("failed to add vrf link: %w", err)
		}

		for _, addr := range vrfConfig.Addresses {
			nlAddr, err := addr.ToNetlinkAddr()
			if err != nil {
				return fmt.Errorf("failed to convert address to netlink addr: %w", err)
			}
			if err := handle.AddrAdd(link, nlAddr); err != nil {
				return fmt.Errorf("failed to add address to vrf link: %w", err)
			}
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set vrf link up: %w", err)
		}

		return nil
	})
}

func (vrfChangeSet *VRFChangeSet) HasUpdates() bool {
	if vrfChangeSet == nil {
		return false
	}

	return len(vrfChangeSet.AddressesToAdd)+len(vrfChangeSet.AddressesToRemove) > 0
}

func (vrfChangeSet *VRFChangeSet) GetInterfaceName() string {
	return vrfChangeSet.InterfaceName
}

func (vrfChangeSet *VRFChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}

func (vrfChangeSet *VRFChangeSet) Apply(ctx context.Context) error {
	netnsInfo, err := vrfChangeSet.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	return pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vrfChangeSet.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get vrf link: %w", err)
		}

		if vrfChangeSet.NeedToSetUp {
			err := handle.LinkSetUp(link)
			return fmt.Errorf("failed to set vrf link up: %w", err)
		}

		for _, addr := range vrfChangeSet.AddressesToRemove {
			if err := handle.AddrDel(link, addr); err != nil {
				return fmt.Errorf("failed to remove address from vrf link: %w", err)
			}
		}

		for _, addr := range vrfChangeSet.AddressesToAdd {
			if err := handle.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add address to vrf link: %w", err)
			}
		}

		return nil
	})
}

func (vrfConfig *VRFConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	changeSet := new(VRFChangeSet)
	changeSet.InterfaceName = vrfConfig.Name

	netnsInfo, err := vrfConfig.GetNetNsInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		vrfLink, err := handle.LinkByName(vrfConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get vrf link: %w", err)
		}

		upBit := vrfLink.Attrs().Flags & net.FlagUp
		if upBit == 0 {
			changeSet.NeedToSetUp = true
		}

		addrChangeSet, err := pkginterfacecommon.CompareSpecAddrsAgainstActualAddrs(vrfConfig.Addresses, vrfLink, handle)
		if err != nil {
			return fmt.Errorf("failed to compare spec addrs against actual addrs: %w", err)
		}
		changeSet.AddressesToAdd = addrChangeSet.AddressesToAdd
		changeSet.AddressesToRemove = addrChangeSet.AddressesToRemove

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	return changeSet, nil
}

func (vrfList *VRFConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	if vrfList == nil {
		return nil
	}
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, vrfCfg := range vrfList.VRFs {
		if vrfCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &vrfCfg)
	}
	return provisioners
}

func (vrfList *VRFConfigurationList) GetType() string {
	return new(netlink.Vrf).Type()
}

func (vrfChangeSet *VRFChangeSet) GetType() string {
	return new(netlink.Vrf).Type()
}

func (vrfList *VRFConfigurationList) DetectChanges(ctx context.Context, delete bool) (*pkgreconcile.ResourceListChangeSet, error) {
	// todo
	return nil, nil
}

func (vrfConfig *VRFConfig) IsSoftDeleted() bool {
	return vrfConfig.Deleted
}

func (vrfConfig *VRFConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}
