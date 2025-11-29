package utils

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

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

func GetCustomResolver(resolverEndpoint string) (*net.Resolver, error) {
	var customResolver *net.Resolver

	if resolverEndpoint != "" {
		customResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 3 * time.Second,
				}
				return d.DialContext(ctx, network, resolverEndpoint) // Replace with your desired DNS server
			},
		}
	}

	return customResolver, nil
}

func GetRandomFreeUDPPort() (int, error) {
	// Listen on UDP port 0, which means the OS will assign a free port.
	addr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return 0, fmt.Errorf("failed to listen on UDP port: %w", err)
	}
	defer conn.Close() // Ensure the connection is closed when done.

	// Get the assigned local address, which includes the free port.
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port
	return port, nil
}
