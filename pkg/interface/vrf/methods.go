package vrf

import (
	"context"
	"fmt"
	"net"

	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

func (vrfConfig *VRFConfig) GetInterfaceName() string {
	return vrfConfig.Name
}

func (vrfConfig *VRFConfig) GetType() string {
	return new(netlink.Vrf).Type()
}

func (vrfConfig *VRFConfig) CheckExist(ctx context.Context) (bool, error) {
	exist := new(bool)
	*exist = false
	err := pkgnetns.WithNsHandleSafe(ctx, vrfConfig, func(handle *netlink.Handle) error {
		_, err := handle.LinkByName(vrfConfig.Name)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				return nil
			}
			return fmt.Errorf("failed to get vrf link: %w", err)
		}
		*exist = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("failed to check exist: %w", err)
	}
	return *exist, nil
}

func (vrfConfig *VRFConfig) Create(ctx context.Context) error {
	return pkgnetns.WithNsHandleSafe(ctx, vrfConfig, func(handle *netlink.Handle) error {
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
	if vrfChangeSet == nil {
		return nil, fmt.Errorf("vrf change set is nil")
	}
	return vrfChangeSet.origin.GetNetNsInfo(ctx)
}

func (vrfChangeSet *VRFChangeSet) Apply(ctx context.Context) error {
	return pkgnetns.WithNsHandleSafe(ctx, vrfChangeSet, func(handle *netlink.Handle) error {
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

	err := pkgnetns.WithNsHandleSafe(ctx, vrfConfig, func(handle *netlink.Handle) error {
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

func (vrfChangeSet *VRFChangeSet) GetType() string {
	return new(netlink.Vrf).Type()
}

func (vrfConfig *VRFConfig) IsSoftDeleted() bool {
	return vrfConfig.Deleted
}

func (vrfConfig *VRFConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	if vrfConfig == nil {
		return nil, fmt.Errorf("vrf config is nil")
	}

	if vrfConfig.Container == nil {
		return nil, nil
	}

	if vrfConfig.Container.Docker != nil {
		cli, err := pkgutils.DockerCliFromCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
		}
		pidPtr, err := pkgutils.GetContainerNSPid(ctx, cli, *vrfConfig.Container.Docker)
		if err != nil {
			return nil, fmt.Errorf("failed to get container ns pid: %w", err)
		}
		return &pkgnetns.NetNsInfo{Pid: pidPtr}, nil
	}

	if vrfConfig.Container.Podman != nil {
		return nil, fmt.Errorf("podman is not supported yet")
	}

	if vrfConfig.Container.NetnsPath != nil {
		return &pkgnetns.NetNsInfo{NetNsPath: vrfConfig.Container.NetnsPath}, nil
	}

	return nil, fmt.Errorf("no container info found")
}
