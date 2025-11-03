package netns

import (
	"context"
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

type NetNsInfo struct {
	Pid int
}

func WithNsHandle(ctx context.Context, netnsInfo *NetNsInfo, f func(h *netlink.Handle) error) error {
	if netnsInfo == nil {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("failed to create netlink handle: %w", err)
		}
		defer handle.Close()
		return f(handle)
	}

	nsHandle, err := vnetns.GetFromPid(netnsInfo.Pid)
	if err != nil {
		return fmt.Errorf("failed to get netns from docker: %w", err)
	}
	defer nsHandle.Close()

	handle, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer handle.Close()

	return f(handle)
}

func WithNsHandleSafe(ctx context.Context, netnsInfo *NetNsInfo, f func(h *netlink.Handle) error) error {
	return WithNsHandle(ctx, netnsInfo, f)
}

func WithNetnsWGCli(ctx context.Context, netnsInfo *NetNsInfo, hook func(wgCtrlCli *wgctrl.Client) error) error {
	var wgCtrlCli *wgctrl.Client
	var err error

	if netnsInfo != nil {

		nsHandle, err := vnetns.GetFromPid(netnsInfo.Pid)
		if err != nil {
			return fmt.Errorf("failed to get netns: %s", err.Error())
		}
		defer nsHandle.Close()

		hostPid := os.Getpid()
		hostNsHandle, err := vnetns.GetFromPid(hostPid)
		if err != nil {
			return fmt.Errorf("failed to get host netns: %s", err.Error())
		}
		defer hostNsHandle.Close()

		vnetns.Set(nsHandle)
		defer vnetns.Set(hostNsHandle)

		wgCtrlCli, err = wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
		}
		defer wgCtrlCli.Close()
	} else {
		wgCtrlCli, err = wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
		}
		defer wgCtrlCli.Close()
	}

	return hook(wgCtrlCli)
}
