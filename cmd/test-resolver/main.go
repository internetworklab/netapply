package main

import (
	"context"
	"fmt"

	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func test() error {
	resolverEndpoints := []string{
		"", // use system resolver
		"1.1.1.1:53",
		"8.8.8.8:53",
		"[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1001]:53",
		"[2001:4860:4860::8888]:53",
		"[2001:4860:4860::8844]:53",
	}
	udpEndpoints := []string{
		"lax1.exploro.one:12312",
		"www.google.com:443",
		"1.2.3.4:21771",
		"[fe80::1771]:1771",
		"iedon.net:23438",
		"hkg1.exploro.one:57870",
	}

	for _, resolverEndpoint := range resolverEndpoints {
		for _, udpEndpoint := range udpEndpoints {
			resolver, err := pkgutils.GetCustomResolver(resolverEndpoint)
			if err != nil {
				return fmt.Errorf("failed to get custom resolver: %w", err)
			}
			udpAddr, err := pkgutils.TryResolveUDPEndpoint(context.TODO(), udpEndpoint, resolver)
			if err != nil {
				return fmt.Errorf("failed to resolve udp address %s: %w", udpEndpoint, err)
			}
			fmt.Printf("Resolver: %s, UDP Endpoint: %s, Resolved To: %s\n", resolverEndpoint, udpEndpoint, udpAddr.String())
		}
	}
	return nil
}

func main() {
	if err := test(); err != nil {
		panic(err)
	}
}
