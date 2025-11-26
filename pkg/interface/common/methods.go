package common

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"

	pkgstub "github.com/internetworklab/netapply/pkg/interface/stub"

	"github.com/vishvananda/netlink"
)

func (addrConfig *AddressConfig) ToNetlinkAddr() (*netlink.Addr, error) {
	if addrConfig.Peer != nil && addrConfig.Local != nil {
		localIP := net.ParseIP(*addrConfig.Local)
		if localIP == nil {
			return nil, fmt.Errorf("failed to parse local ip: %s", *addrConfig.Local)
		}
		peerIPNet, err := netlink.ParseIPNet(*addrConfig.Peer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer ip: %w", err)
		}
		nlAddr := new(netlink.Addr)
		nlAddr.Peer = peerIPNet
		nlAddr.IPNet = &net.IPNet{
			IP:   localIP,
			Mask: peerIPNet.Mask,
		}

		return nlAddr, nil
	}

	ipobj, ipNet, err := net.ParseCIDR(*addrConfig.CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cidr: %w", err)
	}

	nlAddr := new(netlink.Addr)
	nlAddr.IPNet = ipNet
	nlAddr.IP = ipobj
	return nlAddr, nil
}

// returns (added, removed)
func detectAddrChanges(spec []*netlink.Addr, actual []*netlink.Addr) ([]*netlink.Addr, []*netlink.Addr) {
	specMap := make(map[string]*netlink.Addr)
	for _, addr := range spec {
		specMap[getNetlinkAddrKey(addr)] = addr
	}

	actualMap := make(map[string]*netlink.Addr)
	for _, addr := range actual {
		actualMap[getNetlinkAddrKey(addr)] = addr
	}

	added := make([]*netlink.Addr, 0)
	removed := make([]*netlink.Addr, 0)

	for key, addr := range specMap {
		if _, ok := actualMap[key]; !ok {
			added = append(added, addr)
		}
	}

	for key, addr := range actualMap {
		if _, ok := specMap[key]; !ok {
			removed = append(removed, addr)
		}
	}

	return added, removed
}

func getNetlinkAddrKey(addr *netlink.Addr) string {
	if addr == nil {
		return ""
	}

	if addr.Peer != nil {
		return fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Peer.String())
	}

	if addr.IPNet != nil {
		return addr.IPNet.String()
	}

	return addr.IP.String()
}

func CompareSpecAddrsAgainstActualAddrs(specAddrConfigs []AddressConfig, link netlink.Link, handle *netlink.Handle) (*AddrsChangeSet, error) {
	specAddrs := make([]*netlink.Addr, 0)
	for _, addr := range specAddrConfigs {
		nlAddr, err := addr.ToNetlinkAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to netlink addr: %w", err)
		}
		specAddrs = append(specAddrs, nlAddr)
	}

	actualAddrPtrs := make([]*netlink.Addr, 0)
	actualAddrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list wireguard link addresses: %w", err)
	}
	for _, addr := range actualAddrs {
		actualAddrPtrs = append(actualAddrPtrs, &addr)
	}

	added, removed := detectAddrChanges(specAddrs, actualAddrPtrs)

	return &AddrsChangeSet{
		AddressesToAdd:    added,
		AddressesToRemove: removed,
	}, nil
}

func (containerInfo *ContainerInfo) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	if containerInfo == nil {
		return nil, fmt.Errorf("container info is nil")
	}

	if containerInfo.Docker != nil {
		cli, err := pkgutils.DockerCliFromCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
		}

		pidPtr, err := pkgutils.GetContainerNSPid(ctx, cli, *containerInfo.Docker)
		if err != nil {
			return nil, fmt.Errorf("failed to get container ns pid: %w", err)
		}

		return &pkgnetns.NetNsInfo{Pid: pidPtr}, nil
	}

	if containerInfo.Podman != nil {
		return nil, fmt.Errorf("podman is not supported yet")
	}

	if containerInfo.NetnsPath != nil {
		return &pkgnetns.NetNsInfo{NetNsPath: containerInfo.NetnsPath}, nil
	}

	if containerInfo.HostNetns != nil && *containerInfo.HostNetns {
		pid := os.Getpid()
		return &pkgnetns.NetNsInfo{Pid: &pid}, nil
	}

	return nil, fmt.Errorf("no container info found")
}

func CommonInterfaceStatusFromRes(ctx context.Context, res pkgstub.NetnsAwaredResource) (*CommonInterfaceStatus, error) {
	addressesStatus := new(CommonInterfaceStatus)
	err := pkgnetns.WithNsHandleSafe(ctx, res, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(res.GetInterfaceName())
		if err != nil {
			return fmt.Errorf("failed to get link by name: %w", err)
		}
		addressesStatus.OperState = link.Attrs().OperState.String()
		addressesStatus.Flags = link.Attrs().Flags.String()
		actualAddrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("failed to list wireguard link addresses: %w", err)
		}
		addresses := make([]string, 0)
		for _, addr := range actualAddrs {
			if addr.Peer != nil {
				addresses = append(addresses, fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Peer.String()))
			} else if addr.IPNet != nil {
				addresses = append(addresses, addr.IPNet.String())
			} else {
				addresses = append(addresses, addr.String())
			}
		}
		addressesStatus.Addresses = addresses

		addressesStatus.MTU = link.Attrs().MTU

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses status from link: %w", err)
	}
	return addressesStatus, nil
}

func (addressesStatus *CommonInterfaceStatus) IsEqual(other *CommonInterfaceStatus) bool {
	if addressesStatus == nil {
		return other == nil
	}
	if other == nil {
		return false
	}

	// Compare addresses
	lhs := make([]string, 0)
	lhs = append(lhs, addressesStatus.Addresses...)
	rhs := make([]string, 0)
	rhs = append(rhs, other.Addresses...)
	sort.Strings(lhs)
	sort.Strings(rhs)
	if len(lhs) != len(rhs) {
		return false
	}
	for i := range lhs {
		if lhs[i] != rhs[i] {
			return false
		}
	}

	// Compare MTU
	if addressesStatus.MTU != other.MTU {
		return false
	}
	return true
}
