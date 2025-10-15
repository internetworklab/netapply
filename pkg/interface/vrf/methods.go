package vrf

import (
	"context"
	"fmt"
	"net"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	"github.com/vishvananda/netlink"
)

func TrySetVRF(handle *netlink.Handle, link netlink.Link, vrfName *string) error {
	if vrfName == nil {
		return nil
	}

	if *vrfName == VRFNameDefault || *vrfName == VRFNameEmpty {
		if err := handle.LinkSetNoMaster(link); err != nil {
			return fmt.Errorf("failed to set vrf link no master: %w", err)
		}
		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set vrf link up: %w", err)
		}
		return nil
	}

	vrfLink, err := handle.LinkByName(*vrfName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return fmt.Errorf("failed to get vrf link: %w", err)
		}

		// There is no guarantee that the reconciliation will converged at once,
		// it is the responsibility of the caller to check whether it's converged or not.
		// Hence, if the specified VRF is not found, simply skip, because that VRF might be created later.
		return nil
	}

	if err := handle.LinkSetMaster(link, vrfLink); err != nil {
		return fmt.Errorf("failed to set vrf link master: %w", err)
	}

	if err := handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set vrf link up: %w", err)
	}

	return nil
}

// Returns: (vrfNameToSet, error)
func CheckVRFDiff(handle *netlink.Handle, link netlink.Link, vrfName *string) (*string, error) {
	if vrfName == nil {
		// VRF name in unspecified in spec, so, no checks
		return nil, nil
	}

	if link.Attrs().MasterIndex == DefaultVRFIndex {
		if *vrfName != VRFNameDefault && *vrfName != VRFNameEmpty {
			return vrfName, nil
		}
		return nil, nil
	}

	vrfLink, err := handle.LinkByIndex(link.Attrs().MasterIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get vrf link by master index: %w", err)
	}

	if vrfLink.Attrs().Name != *vrfName {
		return vrfName, nil
	}

	return nil, nil
}

func (vrfConfig *VRFConfig) GetContainerName() *string {
	return vrfConfig.ContainerName
}

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
	return pkgdocker.WithNsHandle(ctx, vrfConfig.ContainerName, func(handle *netlink.Handle) error {
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

func (vrfChangeSet *VRFChangeSet) GetContainerName() *string {
	return vrfChangeSet.ContainerName
}

func (vrfChangeSet *VRFChangeSet) Apply(ctx context.Context) error {
	return pkgdocker.WithNsHandleSafe(ctx, vrfChangeSet.ContainerName, func(handle *netlink.Handle) error {
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
	changeSet.ContainerName = vrfConfig.ContainerName
	changeSet.InterfaceName = vrfConfig.Name

	err := pkgdocker.WithNsHandleSafe(ctx, vrfConfig.ContainerName, func(handle *netlink.Handle) error {
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

func (vrfList VRFConfigurationList) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {
	vrfTy := new(netlink.Vrf).Type()
	provisionerList := make([]pkgreconcile.InterfaceProvisioner, 0)
	for _, vrf := range vrfList {
		provisionerList = append(provisionerList, &vrf)
	}

	return pkgreconcile.DetectChanges(ctx, provisionerList, vrfTy, containers)
}
