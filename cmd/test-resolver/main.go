package main

import (
	"context"
	"log"
	"net"
	"time"

	"flag"
)

// var v6Available = flag.Bool("v6-available", false, "whether IPv6 is available")

func init() {
	flag.Parse()
}

func test1() error {
	udpEndpoints := []string{
		"lax1.exploro.one:12312",
		"www.google.com:443",
		"1.2.3.4:21771",
		"[fe80::1771]:1771",
		"[fe80::1771%eth0]:1771",
		"iedon.net:23438",
		"hkg1.exploro.one:57870",
		"github.com:13134",
	}

	// A nil *Resolver is equivalent to a zero Resolver.
	var resolver *net.Resolver

	for _, endpoint := range udpEndpoints {
		hostPart, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			log.Printf("Invalid endpoint %s, can't not split into host and port: %v", endpoint, err)
			continue
		}

		log.Printf("Resolving host %s", hostPart)
		func() {

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ipAddrs, err := resolver.LookupIPAddr(ctx, hostPart)
			if err != nil {
				log.Printf("Failed to resolve host %s: %v", hostPart, err)
				return
			}
			for _, ipAddr := range ipAddrs {
				log.Printf("Host %s resolved to %s, zone: %s, isV4: %t", hostPart, ipAddr.IP.String(), ipAddr.Zone, ipAddr.IP.To4() != nil)
			}
		}()
	}

	return nil
}

// func test() error {
// 	resolverEndpoints := []string{
// 		"", // use system resolver
// 		"1.1.1.1:53",
// 		"8.8.8.8:53",
// 		"[2606:4700:4700::1111]:53",
// 		"[2606:4700:4700::1001]:53",
// 		"[2001:4860:4860::8888]:53",
// 		"[2001:4860:4860::8844]:53",
// 	}
// 	udpEndpoints := []string{
// 		"lax1.exploro.one:12312",
// 		"www.google.com:443",
// 		"1.2.3.4:21771",
// 		"[fe80::1771]:1771",
// 		"[fe80::1771]:177",
// 		"iedon.net:23438",
// 		"hkg1.exploro.one:57870",
// 		"github.com:13134",
// 	}

// 	ctx := context.TODO()
// 	ctx = pkgutils.SetV6AvailableInCtx(ctx, *v6Available)

// 	for _, resolverEndpoint := range resolverEndpoints {
// 		for _, udpEndpoint := range udpEndpoints {
// 			resolver, err := pkgutils.GetCustomResolver(resolverEndpoint)
// 			if err != nil {
// 				return fmt.Errorf("failed to get custom resolver: %w", err)
// 			}

// 			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
// 			udpAddr, err := pkgutils.TryResolveUDPEndpoint(ctx, udpEndpoint, resolver)
// 			if err != nil {
// 				fmt.Printf("failed to resolve udp address %s: %v", udpEndpoint, err)
// 			}
// 			cancel()
// 			fmt.Printf("Resolver: %s, UDP Endpoint: %s, Resolved To: %s\n", resolverEndpoint, udpEndpoint, udpAddr.String())
// 		}
// 	}
// 	return nil
// }

func main() {
	if err := test1(); err != nil {
		panic(err)
	}
}
