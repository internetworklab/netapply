package vxlan

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

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetContainerName() *string {
	return vxlanInterfaceChangeSet.ContainerName
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetInterfaceName() string {
	return vxlanInterfaceChangeSet.InterfaceName
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) HasUpdates() bool {
	return vxlanInterfaceChangeSet != nil && (len(vxlanInterfaceChangeSet.AddressesToAdd) > 0 ||
		len(vxlanInterfaceChangeSet.AddressedToRemove) > 0 ||
		vxlanInterfaceChangeSet.MTUToSet != nil)
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) Apply(ctx context.Context) error {
	if vxlanInterfaceChangeSet == nil {
		return nil
	}

	netnsInfo, err := vxlanInterfaceChangeSet.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	return pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vxlanInterfaceChangeSet.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get vxlan link: %w", err)
		}

		for _, addr := range vxlanInterfaceChangeSet.AddressedToRemove {
			if err := handle.AddrDel(link, addr); err != nil {
				return fmt.Errorf("failed to remove address from vxlan link: %w", err)
			}
		}

		for _, addr := range vxlanInterfaceChangeSet.AddressesToAdd {
			if err := handle.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add address to vxlan link: %w", err)
			}
		}

		if vxlanInterfaceChangeSet.MTUToSet != nil {
			if err := handle.LinkSetMTU(link, *vxlanInterfaceChangeSet.MTUToSet); err != nil {
				return fmt.Errorf("failed to set vxlan link mtu: %w", err)
			}
		}

		return nil
	})
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetChangedItems() map[string]bool {
	changedItems := make(map[string]bool)
	changedItems["Addresses"] = len(vxlanInterfaceChangeSet.AddressesToAdd)+len(vxlanInterfaceChangeSet.AddressedToRemove) > 0
	changedItems["MTU"] = vxlanInterfaceChangeSet.MTUToSet != nil
	return changedItems
}

func (vxlanConfig *VXLANConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	changeSet := new(VXLANInterfaceChangeSet)
	changeSet.ContainerName = vxlanConfig.ContainerName
	changeSet.InterfaceName = vxlanConfig.Name

	netnsInfo, err := vxlanConfig.GetNetNsInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vxlanConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get vxlan link: %w", err)
		}

		if vxlanConfig.MTU != nil {
			if *vxlanConfig.MTU != link.Attrs().MTU {
				changeSet.MTUToSet = vxlanConfig.MTU
			}
		}

		addrsChangeSet, err := pkginterfacecommon.CompareSpecAddrsAgainstActualAddrs(vxlanConfig.Addresses, link, handle)
		if err != nil {
			return fmt.Errorf("failed to compare spec addrs against actual addrs: %w", err)
		}
		changeSet.AddressesToAdd = addrsChangeSet.AddressesToAdd
		changeSet.AddressedToRemove = addrsChangeSet.AddressesToRemove

		return nil
	})

	return changeSet, nil
}

func (vxlanConfig *VXLANConfig) GetContainerName() *string {
	return vxlanConfig.ContainerName
}

func (vxlanConfig *VXLANConfig) GetInterfaceName() string {
	return vxlanConfig.Name
}

func (vxlanConfig *VXLANConfig) Create(ctx context.Context) error {
	netnsInfo, err := vxlanConfig.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	return pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {

		link := &netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name: vxlanConfig.Name,
			},
			VxlanId: int(vxlanConfig.VXLANID & uint32(0x00FFFFFF)),
		}

		if vxlanConfig.LocalIP != nil {
			srcAddr := net.ParseIP(*vxlanConfig.LocalIP)
			if srcAddr == nil {
				return fmt.Errorf("failed to parse local ip: %w", err)
			}
			link.SrcAddr = srcAddr
		}

		if vxlanConfig.MTU != nil {
			link.MTU = *vxlanConfig.MTU
		}

		if vxlanConfig.Nolearning != nil {
			link.Learning = !*vxlanConfig.Nolearning
		}

		if vxlanConfig.Dev != nil {
			underlayLink, err := handle.LinkByName(*vxlanConfig.Dev)
			if err != nil {
				return fmt.Errorf("failed to get underlay link: %w", err)
			}

			link.VtepDevIndex = underlayLink.Attrs().Index
		}

		if vxlanConfig.DestPort != nil {
			link.Port = int(*vxlanConfig.DestPort)
		}

		err = handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add vxlan link: %w", err)
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set vxlan link up: %w", err)
		}

		return nil
	})
}

func (vxlanCfgsList *VXLANConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	if vxlanCfgsList == nil {
		return nil
	}
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, vxlanCfg := range vxlanCfgsList.VXLANConfigs {
		if vxlanCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &vxlanCfg)
	}
	return provisioners
}

func (vxlanCfgsList *VXLANConfigurationList) GetType() string {
	return new(netlink.Vxlan).Type()
}

func (vxlanConfig *VXLANConfig) GetType() string {
	return new(netlink.Vxlan).Type()
}

func (vxlanConfig *VXLANConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, vxlanConfig)
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetType() string {
	return new(netlink.Vxlan).Type()
}

func (vxlanCfgsList *VXLANConfigurationList) DetectChanges(ctx context.Context, delete bool) (*pkgreconcile.ResourceListChangeSet, error) {
	return nil, nil
}

func (vxlanConfig *VXLANConfig) IsSoftDeleted() bool {
	return vxlanConfig.Deleted
}

func (vxlanConfig *VXLANConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}
