package main

import (
	"bytes"
	"fmt"
	"net"
	"os"

	"encoding/json"
	"strings"

	netlink "github.com/vishvananda/netlink"
	wgctrl "golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	yaml "gopkg.in/yaml.v3"
)

type WGConfigIface struct {
	PrivateKeyFile *string `json:"privatekeyfile,omitempty"`
	PrivateKey     *string `json:"privatekey,omitempty"`
	ListenPort     int     `json:"listenport"`
}

type WGConfigPeer struct {
	Publickey  string   `json:"publickey"`
	Endpoint   string   `json:"endpoint"`
	Allowedips []string `json:"allowedips"`
}

func (wgConfPeer *WGConfigPeer) ToPeerConf() (*wgtypes.PeerConfig, error) {
	keyObj, err := wgtypes.ParseKey(wgConfPeer.Publickey)
	if err != nil {
		return nil, err
	}
	peerConf := new(wgtypes.PeerConfig)
	peerConf.PublicKey = keyObj
	endpoint, err := net.ResolveUDPAddr("udp", wgConfPeer.Endpoint)
	if err != nil {
		return nil, err
	}
	peerConf.Endpoint = endpoint
	for _, allowedip := range wgConfPeer.Allowedips {
		_, ipnet, err := net.ParseCIDR(allowedip)
		if err != nil {
			return nil, err
		}
		peerConf.AllowedIPs = append(peerConf.AllowedIPs, *ipnet)
	}
	return peerConf, nil
}

type WGConfigAddr struct {
	Peer  *string `json:"peer,omitempty"`
	Local *string `json:"local,omitempty"`
	CIDR  *string `json:"cidr,omitempty"`
}

func (wgConfAddr *WGConfigAddr) ToAddrConf() (*netlink.Addr, error) {
	if wgConfAddr.Peer != nil && wgConfAddr.Local != nil {
		_, ipnet, err := net.ParseCIDR(*wgConfAddr.Peer)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(*wgConfAddr.Local)
		if ip == nil {
			return nil, fmt.Errorf("invalid local address: %s", *wgConfAddr.Local)
		}
		addrObj := new(netlink.Addr)
		addrObj.IPNet = new(net.IPNet)
		addrObj.IPNet = ipnet
		addrObj.IP = ip
		return addrObj, nil
	} else if wgConfAddr.CIDR != nil {
		_, ipnet, err := net.ParseCIDR(*wgConfAddr.CIDR)
		if err != nil {
			return nil, err
		}
		addrObj := new(netlink.Addr)
		addrObj.IPNet = ipnet
		return addrObj, nil
	}
	return nil, fmt.Errorf("invalid address: %v", wgConfAddr)
}

type WGConfig struct {
	Name      string         `json:"name"`
	Interface WGConfigIface  `json:"interface"`
	Peers     []WGConfigPeer `json:"peers,omitempty"`
	Addresses []WGConfigAddr `json:"addresses,omitempty"`
	MTU       *int           `json:"mtu,omitempty"`
}

func loadWGConfig(configPath string) (*WGConfig, error) {
	wgConfObj := new(WGConfig)
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if strings.HasSuffix(configPath, ".json") {
		err = json.NewDecoder(file).Decode(wgConfObj)

	} else if strings.HasSuffix(configPath, ".yaml") {
		err = yaml.NewDecoder(file).Decode(wgConfObj)
	} else {
		return nil, fmt.Errorf("invalid config file: %s", configPath)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to decode config file: %s", err)
	}
	return wgConfObj, nil
}

func setupWGInterface(wgConf *WGConfig) error {
	ifaceName := wgConf.Name
	var link netlink.Link
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return fmt.Errorf("failed to get link: %s", err)
		}

		link := new(netlink.Wireguard)
		link.Attrs().Name = wgConf.Name
		err = netlink.LinkAdd(link)
	}

	if err != nil {
		return fmt.Errorf("failed to find or add link: %s", err)
	}

	if wgConf.MTU != nil {
		netlink.LinkSetMTU(link, *wgConf.MTU)
	}

	wgCtrl, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to create wgctrl: %s", err)
	}
	defer wgCtrl.Close()

	var pk string
	if wgConf.Interface.PrivateKeyFile != nil {
		pkBytes, err := os.ReadFile(*wgConf.Interface.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %s", err)
		}
		pk = string(bytes.TrimSpace(pkBytes))
	} else if wgConf.Interface.PrivateKey != nil {
		pk = *wgConf.Interface.PrivateKey
	} else {
		return fmt.Errorf("private key is required")
	}

	pkObj, err := wgtypes.ParseKey(pk)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	wgConfObj := new(wgtypes.Config)
	wgConfObj.PrivateKey = &pkObj
	wgConfObj.ListenPort = &wgConf.Interface.ListenPort

	for _, peer := range wgConf.Peers {
		peerConf, err := peer.ToPeerConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert WG config peer to peer config: %v\n", err)
			continue
		}

		wgConfObj.Peers = append(wgConfObj.Peers, *peerConf)
	}

	for _, addr := range wgConf.Addresses {
		addrConf, err := addr.ToAddrConf()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert WG config addr to addr config: %v\n", err)
			continue
		}

		if err := netlink.AddrAdd(link, addrConf); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add address to WG interface: %v\n", err)
		}
	}

	err = wgCtrl.ConfigureDevice(ifaceName, *wgConfObj)
	if err != nil {
		return fmt.Errorf("failed to configure WG interface: %s", err)
	}
	return nil

}

func main() {
	for _, configPath := range os.Args[1:] {
		wgConf, err := loadWGConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load WG config: %v\n", err)
			continue
		}

		if err := setupWGInterface(wgConf); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to setup WG interface: %v\n", err)
			continue
		}
	}
}
