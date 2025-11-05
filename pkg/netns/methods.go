package netns

import (
	"context"
	"fmt"
	"os"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func toNsHandle(netnsInfo *NetNsInfo) (*vnetns.NsHandle, error) {
	if netnsInfo != nil {
		if netnsInfo.Pid != nil {
			pidHandle, err := vnetns.GetFromPid(*netnsInfo.Pid)
			if err != nil {
				return nil, fmt.Errorf("failed to get netns from pid: %w", err)
			}
			return &pidHandle, nil
		} else if netnsInfo.NetNsPath != nil {
			pathNsHandle, err := vnetns.GetFromPath(*netnsInfo.NetNsPath)
			if err != nil {
				return nil, fmt.Errorf("failed to get netns from path: %w", err)
			}
			return &pathNsHandle, nil
		}
	}
	return nil, nil
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
		nsHandle, err := toNsHandle(&netnsInfo)
		if err != nil {
			return fmt.Errorf("failed to get netns handle: %w", err)
		}
		err = func(nshandle *vnetns.NsHandle) error {
			defer nshandle.Close()

			handle, err := netlink.NewHandleAt(*nshandle)
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

	var nsHandle *vnetns.NsHandle = nil

	nsHandle, err = toNsHandle(netnsInfo)
	if err != nil {
		return fmt.Errorf("failed to get netns handle: %w", err)
	}
	defer nsHandle.Close()

	if nsHandle != nil {
		defer nsHandle.Close()
	}

	if nsHandle == nil {
		return withHostNetnsHandle(f)
	}

	handle, err := netlink.NewHandleAt(*nsHandle)
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

	nsHandle, err := toNsHandle(netnsInfo)
	if err != nil {
		return fmt.Errorf("failed to get netns handle: %w", err)
	}

	if nsHandle == nil {
		wgCtrlCli, err = wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
		}
		defer wgCtrlCli.Close()
		return hook(wgCtrlCli)
	}

	defer nsHandle.Close()

	hostPid := os.Getpid()
	hostNsHandle, err := vnetns.GetFromPid(hostPid)
	if err != nil {
		return fmt.Errorf("failed to get host netns: %s", err.Error())
	}
	defer hostNsHandle.Close()

	vnetns.Set(*nsHandle)
	defer vnetns.Set(hostNsHandle)

	wgCtrlCli, err = wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to get wgctrl client: %s", err.Error())
	}
	defer wgCtrlCli.Close()

	return hook(wgCtrlCli)
}
