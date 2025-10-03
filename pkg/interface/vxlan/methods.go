package vxlan

import (
	"context"
	"fmt"
	"net"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
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

	return pkgdocker.WithNsHandle(ctx, vxlanInterfaceChangeSet.ContainerName, func(handle *netlink.Handle) error {
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

	err := pkgdocker.WithNsHandle(ctx, vxlanConfig.ContainerName, func(handle *netlink.Handle) error {
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

	return changeSet, err
}

func (vxlanConfig *VXLANConfig) GetContainerName() *string {
	return vxlanConfig.ContainerName
}

func (vxlanConfig *VXLANConfig) GetInterfaceName() string {
	return vxlanConfig.Name
}

func (vxlanConfig *VXLANConfig) Create(ctx context.Context) error {
	return pkgdocker.WithNsHandle(ctx, vxlanConfig.ContainerName, func(handle *netlink.Handle) error {
		var err error

		link := &netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name: vxlanConfig.Name,
			},
			VxlanId: vxlanConfig.VXLANID,
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

func (vxlanList VXLANConfigurationList) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {
	vxlanty := new(netlink.Vxlan).Type()
	provisionerList := make([]pkgreconcile.InterfaceProvisioner, 0)
	for _, vxlan := range vxlanList {
		provisionerList = append(provisionerList, &vxlan)
	}
	return pkgreconcile.DetectChangesFromProvisionerList(ctx, provisionerList, vxlanty, containers)
}
