package vrf

import (
	"context"
	"fmt"

	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
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
