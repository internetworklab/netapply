package vrf_test

import (
	"context"
	"testing"

	"github.com/docker/docker/client"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacedummy "github.com/internetworklab/netapply/pkg/interface/dummy"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkginterfacevrf "github.com/internetworklab/netapply/pkg/interface/vrf"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

const TestDummyIfName = "dummy-test"
const TestVRFIfName = "vrf-test"

func TestVRF(t *testing.T) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()
	ctx := pkgutils.SetDockerCliInCtx(context.Background(), cli)

	handle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("failed to create netlink handle: %v", err)
	}
	defer handle.Close()

	dummyTestCfg := pkginterfacedummy.DummyConfig{
		Name: TestDummyIfName,
	}
	t.Logf("Creating %s\n", dummyTestCfg.Name)
	if err := dummyTestCfg.Create(ctx); err != nil {
		t.Fatalf("failed to create %s: %v", dummyTestCfg.Name, err)
	}
	defer func() {
		t.Logf("Cleaning up %s\n", dummyTestCfg.Name)
		stubInterfaceChangeSet := pkginterfacestub.StubInterfaceCanceller{
			InterfaceName: dummyTestCfg.Name,
			ContainerName: dummyTestCfg.ContainerName,
		}
		if err := stubInterfaceChangeSet.Cancel(ctx); err != nil {
			t.Fatalf("failed to cancel stub interface: %v", err)
		}
	}()
	t.Logf("%s is created\n", dummyTestCfg.Name)

	vrfTestCfg := pkginterfacevrf.VRFConfig{
		Name:    TestVRFIfName,
		TableId: 1491,
		Addresses: []pkginterfacecommon.AddressConfig{
			{
				CIDR: pkgutils.StringPtr("1.2.3.0/24"),
			},
		},
	}
	t.Logf("Creating %s\n", vrfTestCfg.Name)
	if err := vrfTestCfg.Create(ctx); err != nil {
		t.Fatalf("failed to create %s: %v", vrfTestCfg.Name, err)
	}
	defer func() {
		t.Logf("Cleaning up %s\n", vrfTestCfg.Name)
		stubInterfaceChangeSet := pkginterfacestub.StubInterfaceCanceller{
			InterfaceName: vrfTestCfg.Name,
			ContainerName: vrfTestCfg.ContainerName,
		}
		if err := stubInterfaceChangeSet.Cancel(ctx); err != nil {
			t.Fatalf("failed to cancel stub interface: %v", err)
		}
		t.Logf("%s is cleaned up\n", vrfTestCfg.Name)
	}()

	t.Logf("%s is created\n", vrfTestCfg.Name)

	dummyTest, err := handle.LinkByName(dummyTestCfg.Name)
	if err != nil {
		t.Fatalf("failed to get %s link: %v", dummyTestCfg.Name, err)
	}

	t.Logf("%s master index: %d", dummyTestCfg.Name, dummyTest.Attrs().MasterIndex)

	vrfTest, err := handle.LinkByName(vrfTestCfg.Name)
	if err != nil {
		t.Fatalf("failed to get %s link: %v", vrfTestCfg.Name, err)
	}

	t.Logf("Setting %s master to %s\n", dummyTestCfg.Name, vrfTestCfg.Name)
	err = handle.LinkSetMaster(dummyTest, vrfTest)
	if err != nil {
		t.Fatalf("failed to set %s master: %v", dummyTestCfg.Name, err)
	}

	err = handle.LinkSetUp(dummyTest)
	if err != nil {
		t.Fatalf("failed to set %s up: %v", dummyTestCfg.Name, err)
	}

	t.Logf("master of %s is now %s\n", dummyTestCfg.Name, vrfTestCfg.Name)

	dummyTest, err = handle.LinkByName(dummyTestCfg.Name)
	if err != nil {
		t.Fatalf("failed to get %s link: %v", dummyTestCfg.Name, err)
	}

	t.Logf("%s master index after set master: %d", dummyTestCfg.Name, dummyTest.Attrs().MasterIndex)

	vrfTest, err = handle.LinkByName(vrfTestCfg.Name)
	if err != nil {
		t.Fatalf("failed to get %s link: %v", vrfTestCfg.Name, err)
	}

	if dummyTest.Attrs().MasterIndex != vrfTest.Attrs().Index {
		t.Fatalf("master index of %s is not %s", dummyTestCfg.Name, vrfTestCfg.Name)
	}
	t.Logf("Link index of %s: %d", vrfTest.Attrs().Name, vrfTest.Attrs().Index)
}
