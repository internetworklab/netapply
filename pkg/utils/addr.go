package utils

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
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

func StripPortSuffix(endpoint string) (string, string, error) {
	pattern, err := regexp.Compile(`:\d+$`)
	if err != nil {
		return "", "", fmt.Errorf("failed to compile port suffix pattern: %w", err)
	}
	res := pattern.Find([]byte(endpoint))
	if res == nil {
		return "", "", fmt.Errorf("no port suffix is found in endpoint %s", endpoint)
	}
	res = res[1:]

	portStr := string(res)
	portLen := len(portStr)
	if portLen+1 >= len(endpoint) {
		return "", "", fmt.Errorf("invalid endpoint %s", endpoint)
	}

	ipaddrPart := endpoint[:len(endpoint)-portLen-1]

	// to handle IPv6 addresses, like [2001:db8::1]:1234
	ipaddrPart = strings.TrimLeft(ipaddrPart, "[")
	ipaddrPart = strings.TrimRight(ipaddrPart, "]")

	return ipaddrPart, portStr, nil
}

func TryResolveIP(ctx context.Context, host string, resolver *net.Resolver) (net.IP, error) {
	networks := []string{"ip", "ip4", "ip6"}
	for _, nw := range networks {
		ips, err := resolver.LookupNetIP(ctx, nw, host)
		if err == nil && ips != nil {
			if ips[0].Is4() {
				a4 := ips[0].As4()
				return net.IP(a4[:]), nil
			}
			if ips[0].Is6() {
				a6 := ips[0].As16()
				return net.IP(a6[:]), nil
			}
		}
	}
	return nil, fmt.Errorf("failed to resolve IP address for host %s", host)
}

func TryResolveUDPEndpoint(ctx context.Context, endpoint string, resolver *net.Resolver) (*net.UDPAddr, error) {
	if resolver == nil {
		// using system resolver
		return net.ResolveUDPAddr("udp", endpoint)
	}

	hostPart, portPart, err := StripPortSuffix(endpoint)
	if err != nil {
		return nil, err
	}

	ip, err := TryResolveIP(ctx, hostPart, resolver)
	if err != nil {
		return nil, err
	}

	portNum, err := strconv.Atoi(portPart)
	if err != nil {
		return nil, fmt.Errorf("failed to convert port suffix to number: %w", err)
	}

	udpAddr := &net.UDPAddr{
		IP:   ip,
		Port: portNum,
	}
	return udpAddr, nil
}
