package utils

import (
	"net"
	"sort"
)

func IsUDPAddrNotEqu(spec, curr *net.UDPAddr) bool {
	if spec == nil || curr == nil {
		return false
	}

	return spec.String() != curr.String()
}

func IsIPNetListNotEqu(lhs, rhs []net.IPNet) bool {
	lhsStrs := make([]string, 0)
	for _, allowedIP := range lhs {
		lhsStrs = append(lhsStrs, allowedIP.String())
	}

	rhsStrs := make([]string, 0)
	for _, allowedIP := range rhs {
		rhsStrs = append(rhsStrs, allowedIP.String())
	}

	sort.Strings(lhsStrs)
	sort.Strings(rhsStrs)

	if len(lhsStrs) != len(rhsStrs) {
		return true
	}

	for i := range lhsStrs {
		if lhsStrs[i] != rhsStrs[i] {
			return true
		}
	}

	return false
}

// For IPv4, append /32 VLSM to make it a CIDR with full 32 bits mask,
// For IPv6, append /128 VLSM to make it a CIDR with full 128 bits mask.
func WithFullMaskIPNet(ipObj net.IP) *net.IPNet {
	if ipObj == nil {
		return nil
	}

	ip4 := ipObj.To4()
	if ip4 != nil {
		ipnet := &net.IPNet{
			IP:   ip4,
			Mask: net.CIDRMask(32, 32),
		}
		return ipnet
	}
	ipnet := &net.IPNet{
		IP:   ipObj,
		Mask: net.CIDRMask(128, 128),
	}
	return ipnet
}

// This works the same as WithFullMaskIPNet, except that it's string in and string out.
func WithFullMask(ip *string) *string {
	if ip == nil || *ip == "" {
		return nil
	}

	ipObj := net.ParseIP(*ip)
	if ipObj == nil {
		return nil
	}
	ipnet := WithFullMaskIPNet(ipObj)
	if ipnet == nil {
		return nil
	}
	str := ipnet.String()

	return &str
}
