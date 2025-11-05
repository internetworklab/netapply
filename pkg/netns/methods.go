package netns

import (
	"context"
	"fmt"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func (netnsInfo *NetNsInfo) ToNsHandle() (vnetns.NsHandle, error) {
	if netnsInfo == nil {
		return vnetns.Get()
	}

	if netnsInfo.Pid != nil {
		return vnetns.GetFromPid(*netnsInfo.Pid)
	}

	if netnsInfo.NetNsPath != nil {
		return vnetns.GetFromPath(*netnsInfo.NetNsPath)
	}

	return -1, fmt.Errorf("invalid netns info, no idea know how to obtain a netns handle from it")
}

// returns a string which uniquely identifies the namespace associated with the network handle.
// when working with multi-netns reconciliation, one needs such a key to uniquely identify the namespace where the resource is associated with.
func (netnsInfo *NetNsInfo) ToNetnsKey() (string, error) {
	nsHandle, err := netnsInfo.ToNsHandle()
	if err != nil {
		return "", fmt.Errorf("failed to get netns unique key: %w", err)
	}

	return nsHandle.UniqueId(), nil
}

func withHostNetnsHandle(f func(h *netlink.Handle) error) error {
	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer handle.Close()
	return f(handle)
}

func WithMultiNetnsHandle(ctx context.Context, res MultiNetnsResource, f func(h *netlink.Handle, netnsInfo *NetNsInfo) error) error {
	netnsInfos, err := res.GetNetNsInfos(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns infos: %w", err)
	}

	if len(netnsInfos) == 0 {
		return withHostNetnsHandle(func(h *netlink.Handle) error {
			return f(h, nil)
		})
	}

	for _, netnsInfo := range netnsInfos {
		nsHandle, err := netnsInfo.ToNsHandle()
		if err != nil {
			return fmt.Errorf("failed to get netns handle: %w", err)
		}
		err = func(nshandle vnetns.NsHandle) error {
			defer nshandle.Close()

			handle, err := netlink.NewHandleAt(nshandle)
			if err != nil {
				return fmt.Errorf("failed to create netlink handle: %w", err)
			}
			defer handle.Close()

			return f(handle, &netnsInfo)
		}(nsHandle)
		if err != nil {
			return fmt.Errorf("failed to run function: %w", err)
		}
	}

	return nil
}

func WithNsHandle(ctx context.Context, res NetNsAwareResource, f func(h *netlink.Handle) error) error {
	netnsInfo, err := res.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	nsHandle, err := netnsInfo.ToNsHandle()
	if err != nil {
		return fmt.Errorf("failed to get netns handle: %w", err)
	}
	defer nsHandle.Close()

	handle, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer handle.Close()

	return f(handle)
}

func WithNsHandleSafe(ctx context.Context, res NetNsAwareResource, f func(h *netlink.Handle) error) error {
	return WithNsHandle(ctx, res, f)
}

func WithNetnsWGCli(ctx context.Context, res NetNsAwareResource, hook func(wgCtrlCli *wgctrl.Client) error) error {
	netnsInfo, err := res.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get netns info: %w", err)
	}

	var wgCtrlCli *wgctrl.Client

	nsHandle, err := netnsInfo.ToNsHandle()
	if err != nil {
		return fmt.Errorf("failed to get netns handle: %w", err)
	}
	defer nsHandle.Close()

	hostNsHandle, err := vnetns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host netns handle: %w", err)
	}
	defer hostNsHandle.Close()

	vnetns.Set(nsHandle)
	defer vnetns.Set(hostNsHandle)

	wgCtrlCli, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
	}
	defer wgCtrlCli.Close()

	return hook(wgCtrlCli)
}
