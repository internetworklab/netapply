package vrf_test

import (
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestVRF(t *testing.T) {

	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("failed to create netlink handle: %v", err)
	}
	defer handle.Close()

	// Create dummy0 and vrf42
	err = func() error {
		handle, err := netlink.NewHandle()
		if err != nil {
			t.Fatalf("failed to create netlink handle: %v", err)
		}
		defer handle.Close()

		dummy0 := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: "dummy0",
			},
		}
		err = handle.LinkAdd(dummy0)
		if err != nil {
			return fmt.Errorf("failed to add dummy0 link: %w", err)
		}

		err = handle.LinkSetUp(dummy0)
		if err != nil {
			return fmt.Errorf("failed to set dummy0 up: %w", err)
		}

		t.Logf("dummy0 is created\n")

		vrf0 := &netlink.Vrf{
			LinkAttrs: netlink.LinkAttrs{
				Name: "vrf0",
			},
			Table: 1491,
		}
		err = handle.LinkAdd(vrf0)
		if err != nil {
			return fmt.Errorf("failed to add vrf0 link: %w", err)
		}

		err = handle.LinkSetUp(vrf0)
		if err != nil {
			return fmt.Errorf("failed to set vrf0 up: %w", err)
		}

		t.Logf("vrf0 is created\n")

		return nil
	}()
	if err != nil {
		t.Fatalf("failed to create dummy0 and vrf42: %v", err)
	}

	dummy0, err := handle.LinkByName("dummy0")
	if err != nil {
		t.Fatalf("failed to get dummy0 link: %v", err)
	}

	t.Logf("dummy0 master index: %d", dummy0.Attrs().MasterIndex)

	vrf0, err := handle.LinkByName("vrf0")
	if err != nil {
		t.Fatalf("failed to get vrf0 link: %v", err)
	}

	t.Logf("Setting dummy0 master to vrf0\n")
	err = handle.LinkSetMaster(dummy0, vrf0)
	if err != nil {
		t.Fatalf("failed to set dummy0 master: %v", err)
	}

	err = handle.LinkSetUp(dummy0)
	if err != nil {
		t.Fatalf("failed to set dummy0 up: %v", err)
	}

	t.Logf("master of dummy0 is now vrf0\n")

	dummy0, err = handle.LinkByName("dummy0")
	if err != nil {
		t.Fatalf("failed to get dummy0 link: %v", err)
	}

	t.Logf("dummy0 master index after set master: %d", dummy0.Attrs().MasterIndex)

	if err := handle.LinkDel(dummy0); err != nil {
		t.Fatalf("failed to delete dummy0 link: %v", err)
	}
	t.Logf("dummy0 is deleted\n")

	if err := handle.LinkDel(vrf0); err != nil {
		t.Fatalf("failed to delete vrf0 link: %v", err)
	}
	t.Logf("vrf0 is deleted\n")
}
