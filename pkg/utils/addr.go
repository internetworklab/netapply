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
