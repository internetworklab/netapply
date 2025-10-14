package vxlan_test

import (
	"context"
	"testing"

	"github.com/docker/docker/client"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkginterfacevxlan "github.com/internetworklab/netapply/pkg/interface/vxlan"
	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

// We use vx-test and wg-test for names of the testing interfaces.
// Please enasure that these names are not in used before running the test.

func TestVXLANConfig(t *testing.T) {

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	ctx := pkgutils.SetDockerCliInCtx(context.Background(), cli)

	wgCfg := pkginterfacewireguard.WireGuardConfig{
		Name:          "wg-test",
		ContainerName: nil,
		ListenPort:    pkgutils.IntPtr(10086),
		MTU:           pkgutils.IntPtr(1450),
		PrivateKey:    "CPcEAcp+yaFfHDhldiDczchxeGJNN5+xjx/E98zJFnY=",
	}

	vxlanCfg := pkginterfacevxlan.VXLANConfig{
		Name:          "vx-test",
		ContainerName: nil,
		Dev:           pkgutils.StringPtr(wgCfg.Name),
		VXLANID:       15001,
		DestPort:      pkgutils.Uint16Ptr(4789),
	}

	t.Logf("Setting up wireguard interface %s", wgCfg.Name)
	if err := wgCfg.Create(ctx); err != nil {
		t.Fatalf("failed to apply wireguard interface: %v", err)
	}
	t.Logf("Wireguard interface %s created", wgCfg.Name)
	defer func() {
		t.Logf("Cleaning up wireguard interface %s", wgCfg.Name)
		stubInterfaceChangeSet := pkginterfacestub.StubInterfaceCanceller{
			InterfaceName: wgCfg.Name,
			ContainerName: wgCfg.ContainerName,
		}
		if err := stubInterfaceChangeSet.Cancel(ctx); err != nil {
			t.Fatalf("failed to cancel stub interface: %v", err)
		}
		t.Logf("Wireguard interface %s cleaned up", wgCfg.Name)
	}()

	t.Logf("Setting up vxlan interface %s", vxlanCfg.Name)
	if err := vxlanCfg.Create(ctx); err != nil {
		t.Fatalf("failed to apply vxlan interface: %v", err)
	}
	t.Logf("Vxlan interface %s created", vxlanCfg.Name)
	defer func() {
		t.Logf("Cleaning up vxlan interface %s", vxlanCfg.Name)
		stubInterfaceChangeSet := pkginterfacestub.StubInterfaceCanceller{
			InterfaceName: vxlanCfg.Name,
			ContainerName: vxlanCfg.ContainerName,
		}
		if err := stubInterfaceChangeSet.Cancel(ctx); err != nil {
			t.Fatalf("failed to cancel stub interface: %v", err)
		}
		t.Logf("Vxlan interface %s cleaned up", vxlanCfg.Name)
	}()

	nsHandle, err := netlink.NewHandle()
	if err != nil {
		t.Fatalf("failed to create netlink handle: %v", err)
	}
	defer nsHandle.Close()

	vxlanLinkUnknown, err := nsHandle.LinkByName(vxlanCfg.Name)
	if err != nil {
		t.Fatalf("failed to get vxlan link: %v", err)
	}

	vxlanLink, ok := vxlanLinkUnknown.(*netlink.Vxlan)
	if !ok {
		t.Fatalf("vxlan link %s is not a vxlan link", vxlanCfg.Name)
	}

	t.Logf("Vxlan link %s found", vxlanCfg.Name)
	t.Logf("Dev index: %d", vxlanLink.VtepDevIndex)

	wgLink, err := nsHandle.LinkByName(wgCfg.Name)
	if err != nil {
		t.Fatalf("failed to get wireguard link: %v", err)
	}
	t.Logf("WireGuard link %s found", wgCfg.Name)
	t.Logf("Link index: %d", wgLink.Attrs().Index)

}
