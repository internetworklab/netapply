package common

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func (addrConfig *AddressConfig) ToNetlinkAddr() (*netlink.Addr, error) {
	if addrConfig.Peer != nil && addrConfig.Local != nil {
		peerIPObj, peerIPNet, err := net.ParseCIDR(*addrConfig.Peer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer ip: %w", err)
		}

		localIp := net.ParseIP(*addrConfig.Local)
		if localIp == nil {
			return nil, fmt.Errorf("failed to parse local ip: %w", err)
		}

		nlAddr := new(netlink.Addr)
		nlAddr.Peer = new(net.IPNet)
		nlAddr.Peer = peerIPNet
		nlAddr.Peer.IP = peerIPObj
		nlAddr.IPNet = new(net.IPNet)
		nlAddr.IP = localIp

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
