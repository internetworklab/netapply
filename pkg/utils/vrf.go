package utils

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

const VRFNameEmpty = ""
const VRFNameDefault = "default"

// If the master index of a link is 0, we consider its VRF as default VRF
const DefaultVRFIndex int = 0

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
		return fmt.Errorf("failed to get vrf link: %w", err)
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
