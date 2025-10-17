package utils

import (
	"fmt"
	"log"
	"net"
	"time"
)

func TryResolveUDPAddrManyTimes(addr string, retries int, retryIntvl time.Duration) (*net.UDPAddr, error) {
	var err error
	for i := 0; i < retries; i++ {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err == nil {
			return udpAddr, nil
		}
		log.Printf("failed to resolve udp address %s: %v", addr, err)
		log.Printf("will retry in %s", retryIntvl)
		time.Sleep(retryIntvl)
	}
	return nil, fmt.Errorf("failed to resolve udp address %s: %w", addr, err)
}
