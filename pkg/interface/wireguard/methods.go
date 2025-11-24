package wireguard

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetChangedItems() map[string]bool {
	changedItems := make(map[string]bool)
	changedItems["PrivateKey"] = wgInterfaceChangeSet.PrivateKeyToSet != nil
	changedItems["ListenPort"] = wgInterfaceChangeSet.ListenPortToSet != nil
	changedItems["Peers"] = wgInterfaceChangeSet.PeersToRemove != nil || wgInterfaceChangeSet.PeersToAdd != nil
	changedItems["Addresses"] = wgInterfaceChangeSet.AddressesToAdd != nil || wgInterfaceChangeSet.AddressesToRemove != nil
	changedItems["MTU"] = wgInterfaceChangeSet.MTUToSet != nil
	return changedItems
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) HasUpdates() bool {
	if wgInterfaceChangeSet == nil {
		return false
	}

	if wgInterfaceChangeSet.PrivateKeyToSet != nil {
		log.Printf("wireguard link %s private key changed to %s", wgInterfaceChangeSet.GetInterfaceName(), *wgInterfaceChangeSet.PrivateKeyToSet)
		return true
	}

	if wgInterfaceChangeSet.MTUToSet != nil {
		log.Printf("wireguard link %s mtu changed to %d", wgInterfaceChangeSet.GetInterfaceName(), *wgInterfaceChangeSet.MTUToSet)
		return true
	}

	if wgInterfaceChangeSet.ListenPortToSet != nil {
		log.Printf("wireguard link %s listen port changed to %d", wgInterfaceChangeSet.GetInterfaceName(), *wgInterfaceChangeSet.ListenPortToSet)
		return true
	}

	if len(wgInterfaceChangeSet.PeersToRemove) > 0 {
		log.Printf("wireguard link %s peers removed: %v", wgInterfaceChangeSet.GetInterfaceName(), wgInterfaceChangeSet.PeersToRemove)
		return true
	}

	if len(wgInterfaceChangeSet.PeersToAdd) > 0 {
		log.Printf("wireguard link %s peers added: %v", wgInterfaceChangeSet.GetInterfaceName(), wgInterfaceChangeSet.PeersToAdd)
		return true
	}

	if len(wgInterfaceChangeSet.AddressesToAdd) > 0 {
		log.Printf("wireguard link %s addresses added: %v", wgInterfaceChangeSet.GetInterfaceName(), len(wgInterfaceChangeSet.AddressesToAdd))
		return true
	}

	if len(wgInterfaceChangeSet.AddressesToRemove) > 0 {
		log.Printf("wireguard link %s addresses removed: %v", wgInterfaceChangeSet.GetInterfaceName(), len(wgInterfaceChangeSet.AddressesToRemove))
		return true
	}

	if wgInterfaceChangeSet.VRFToSet != nil {
		log.Printf("wireguard link %s vrf changed to %s", wgInterfaceChangeSet.GetInterfaceName(), *wgInterfaceChangeSet.VRFToSet)
		return true
	}

	return false
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return wgInterfaceChangeSet.origin.GetNetNsInfo(ctx)
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetInterfaceName() string {
	return wgInterfaceChangeSet.origin.GetInterfaceName()
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) Apply(ctx context.Context) error {
	if wgInterfaceChangeSet == nil {
		return nil
	}

	if wgInterfaceChangeSet.PrivateKeyToSet != nil || wgInterfaceChangeSet.ListenPortToSet != nil || wgInterfaceChangeSet.PeersToRemove != nil || wgInterfaceChangeSet.PeersToAdd != nil {
		err := pkgnetns.WithNetnsWGCli(ctx, wgInterfaceChangeSet, func(wgCtrl *wgctrl.Client) error {
			currentConfig, err := wgCtrl.Device(wgInterfaceChangeSet.GetInterfaceName())
			if err != nil {
				return fmt.Errorf("failed to get wireguard device: %w", err)
			}

			if currentConfig == nil {
				return fmt.Errorf("failed to get wireguard device: %s", wgInterfaceChangeSet.GetInterfaceName())
			}

			if wgInterfaceChangeSet.PrivateKeyToSet != nil {
				patchConfig := new(wgtypes.Config)
				patchConfig.PrivateKey = wgInterfaceChangeSet.PrivateKeyToSet
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.GetInterfaceName(), *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			if wgInterfaceChangeSet.ListenPortToSet != nil {
				patchConfig := new(wgtypes.Config)
				patchConfig.ListenPort = wgInterfaceChangeSet.ListenPortToSet
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.GetInterfaceName(), *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			for _, p := range wgInterfaceChangeSet.PeersToRemove {
				patchConfig := new(wgtypes.Config)
				patchConfig.Peers = make([]wgtypes.PeerConfig, 0)
				patchConfig.ReplacePeers = false
				patchConfig.Peers = append(patchConfig.Peers, wgtypes.PeerConfig{
					PublicKey: p.PublicKey,
					Remove:    true,
				})
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.GetInterfaceName(), *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			for _, p := range wgInterfaceChangeSet.PeersToAdd {
				patchConfig := new(wgtypes.Config)
				patchConfig.Peers = make([]wgtypes.PeerConfig, 0)
				patchConfig.ReplacePeers = false
				patchConfig.Peers = append(patchConfig.Peers, p)
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.GetInterfaceName(), *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to apply wireguard config: %w", err)
		}
	}

	err := pkgnetns.WithNsHandle(ctx, wgInterfaceChangeSet, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(wgInterfaceChangeSet.GetInterfaceName())
		if err != nil {
			return fmt.Errorf("failed to get wireguard link: %w", err)
		}

		if wgInterfaceChangeSet.VRFToSet != nil {
			if err := pkgutils.TrySetVRF(handle, link, wgInterfaceChangeSet.VRFToSet); err != nil {
				return fmt.Errorf("failed to set vrf for wireguard link: %w", err)
			}
		}

		if wgInterfaceChangeSet.MTUToSet != nil {
			if err := handle.LinkSetMTU(link, *wgInterfaceChangeSet.MTUToSet); err != nil {
				return fmt.Errorf("failed to set wireguard link mtu: %w", err)
			}
		}

		for _, addr := range wgInterfaceChangeSet.AddressesToRemove {
			if err := handle.AddrDel(link, addr); err != nil {
				return fmt.Errorf("failed to remove wireguard link address: %w", err)
			}
		}

		for _, addr := range wgInterfaceChangeSet.AddressesToAdd {
			fmt.Println("AddrAdd", addr.String())
			if err := handle.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add wireguard link address: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to apply wireguard netlink config: %w", err)
	}

	return nil
}

func (wgConf *WireGuardConfig) GetInterfaceName() string {
	return wgConf.Name
}

func (wgConf *WireGuardConfig) GetType() string {
	return new(netlink.Wireguard).Type()
}

func (wgConf *WireGuardConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, wgConf)
}

// returns: (added, removed)
func checkWGPeersDifference(specPeers []wgtypes.PeerConfig, currentPeers []*wgtypes.Peer) (map[string]wgtypes.PeerConfig, map[string]*wgtypes.Peer) {

	commonPeers := make(map[string]wgtypes.PeerConfig)
	specPeersMap := make(map[string]wgtypes.PeerConfig)
	currentPeersMap := make(map[string]*wgtypes.Peer)
	peersToRemove := make(map[string]*wgtypes.Peer)
	peersToAdd := make(map[string]wgtypes.PeerConfig)

	for _, peer := range specPeers {
		specPeersMap[peer.PublicKey.String()] = peer
	}

	for _, peer := range currentPeers {
		k := peer.PublicKey.String()
		currentPeersMap[k] = peer
		if _, ok := specPeersMap[k]; ok {
			commonPeers[k] = specPeersMap[k]
		} else {
			peersToRemove[k] = peer
		}
	}

	for _, peer := range specPeers {
		if _, ok := currentPeersMap[peer.PublicKey.String()]; !ok {
			peersToAdd[peer.PublicKey.String()] = peer
		}
	}

	for k, spec := range commonPeers {
		peer := currentPeersMap[k]
		if spec.PresharedKey != nil && *spec.PresharedKey != peer.PresharedKey {
			peersToRemove[k] = peer
			peersToAdd[k] = spec
		}

		if spec.Endpoint != nil && peer.Endpoint != nil && spec.Endpoint.String() != peer.Endpoint.String() {
			peersToRemove[k] = peer
			peersToAdd[k] = spec
		}

		if spec.PersistentKeepaliveInterval != nil {
			if *spec.PersistentKeepaliveInterval != peer.PersistentKeepaliveInterval {
				peersToRemove[k] = peer
				peersToAdd[k] = spec
			}
		}

		if pkgutils.IsIPNetListNotEqu(spec.AllowedIPs, peer.AllowedIPs) {
			peersToRemove[k] = peer
			peersToAdd[k] = spec
		}
	}

	return peersToAdd, peersToRemove
}

func (wgConf *WireGuardConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {

	changeSet := new(WireGuardInterfaceChangeSet)
	changeSet.origin = wgConf

	wgtypesConf, err := wgConf.ToWGTypesConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to convert wireguard config to wgtypes config: %w", err)
	}

	specPeerConfigs := make([]wgtypes.PeerConfig, 0)
	for _, peer := range wgConf.Peers {
		peercfg, err := peer.ToWGTypesPeer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer to wgtypes peer of interface %s: %w", wgConf.Name, err)
		}

		specPeerConfigs = append(specPeerConfigs, *peercfg)
	}

	err = pkgnetns.WithNetnsWGCli(ctx, wgConf, func(wgCtrl *wgctrl.Client) error {
		currentConfig, err := wgCtrl.Device(wgConf.Name)
		if err != nil {
			return fmt.Errorf("failed to get wireguard device: %w", err)
		}

		if currentConfig == nil {
			return fmt.Errorf("failed to get wireguard device: %s ", wgConf.Name)
		}

		currPeers := make([]*wgtypes.Peer, 0)
		for _, peer := range currentConfig.Peers {
			currPeers = append(currPeers, &peer)
		}

		addedPeers, removedPeers := checkWGPeersDifference(specPeerConfigs, currPeers)
		changeSet.PeersToAdd = addedPeers
		changeSet.PeersToRemove = removedPeers

		if wgtypesConf.PrivateKey != nil {
			if *wgtypesConf.PrivateKey != currentConfig.PrivateKey {
				changeSet.PrivateKeyToSet = wgtypesConf.PrivateKey
			}
		}

		if wgtypesConf.ListenPort != nil {
			if *wgtypesConf.ListenPort != currentConfig.ListenPort {
				changeSet.ListenPortToSet = wgtypesConf.ListenPort
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for wireguard config: %w", err)
	}

	err = pkgnetns.WithNsHandle(ctx, wgConf, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(wgConf.Name)
		if err != nil {
			return fmt.Errorf("failed to get wireguard link: %w", err)
		}

		if wgConf.VRF != nil {
			vrfDiff, err := pkgutils.CheckVRFDiff(handle, link, wgConf.VRF)
			if err != nil {
				return fmt.Errorf("failed to check vrf diff: %w", err)
			}
			if vrfDiff != nil {
				changeSet.VRFToSet = vrfDiff
				log.Printf("wireguard link %s vrf changed to %s", wgConf.Name, *vrfDiff)
			}
		}

		if wgConf.MTU != nil {
			if *wgConf.MTU != link.Attrs().MTU {
				changeSet.MTUToSet = wgConf.MTU
			}
		}

		addrsChangeSet, err := pkginterfacecommon.CompareSpecAddrsAgainstActualAddrs(wgConf.Addresses, link, handle)
		if err != nil {
			return fmt.Errorf("failed to compare spec addrs against actual addrs: %w", err)
		}
		changeSet.AddressesToAdd = addrsChangeSet.AddressesToAdd
		changeSet.AddressesToRemove = addrsChangeSet.AddressesToRemove

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to detect netlink changes for wireguard interface: %w", err)
	}

	return changeSet, nil
}

func (wgPeerConfig *WireGuardPeerConfig) ToWGTypesPeer(ctx context.Context) (*wgtypes.PeerConfig, error) {
	peercfg := new(wgtypes.PeerConfig)

	pkObj, err := getKeyObj(ctx, wgPeerConfig.PublicKey, wgPeerConfig.PublicKeyFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to get key object: %w", err)
	}
	peercfg.PublicKey = *pkObj

	if wgPeerConfig.PresharedKey != "" || wgPeerConfig.PresharedKeyFrom != nil {
		pskObj, err := getKeyObj(ctx, wgPeerConfig.PresharedKey, wgPeerConfig.PresharedKeyFrom)
		if err != nil {
			return nil, fmt.Errorf("psk specified, but failed to get preshared key object: %w", err)
		}
		peercfg.PresharedKey = pskObj
	}

	if wgPeerConfig.PersistentKeepalive != nil {
		dur := time.Duration(*wgPeerConfig.PersistentKeepalive) * time.Second
		peercfg.PersistentKeepaliveInterval = &dur
	}

	if wgPeerConfig.Endpoint != nil {
		resolverEndpoint, err := pkgutils.ResolverEndpointFromCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get resolver endpoint from context: %w", err)
		}

		resolver, err := pkgutils.GetCustomResolver(resolverEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to get custom resolver: %w", err)
		}
		udpAddr, err := pkgutils.TryResolveUDPEndpoint(ctx, *wgPeerConfig.Endpoint, resolver)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve udp address %s: %w", *wgPeerConfig.Endpoint, err)
		}
		peercfg.Endpoint = udpAddr
	}

	for _, allowedipstr := range wgPeerConfig.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(allowedipstr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed ip: %w", err)
		}
		peercfg.AllowedIPs = append(peercfg.AllowedIPs, *ipnet)
	}

	return peercfg, nil
}

func getKeyObj(ctx context.Context, pkB64 string, pkURL *string) (*wgtypes.Key, error) {
	if pkB64 != "" {
		pkobj, err := wgtypes.ParseKey(strings.TrimSpace(pkB64))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		return &pkobj, nil
	}
	if pkURL != nil && *pkURL != "" {
		var tlsConfig *tls.Config
		clientAuth, err := pkgutils.ClientAuthFromCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get client auth from context: %w", err)
		}

		if strings.HasPrefix(*pkURL, "https://") {
			tlsConfig, err = pkgutils.GetTLSConfig(clientAuth.TLSTrustedCACertFile, clientAuth.TLSClientCertFile, clientAuth.TLSClientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to get TLS config: %w", err)
			}
		}

		reader, err := pkgutils.NewURLReader(*pkURL, &pkgutils.URLReaderTransportOptions{
			TLSConfig: tlsConfig,
			Username:  clientAuth.HTTPBasicAuthUsername,
			Password:  clientAuth.HTTPBasicAuthPassword,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create URL reader: %w", err)
		}
		defer reader.Close()
		pkContent, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
		return getKeyObj(ctx, string(pkContent), nil)
	}
	return nil, fmt.Errorf("private key is not set")
}

func (wgConf *WireGuardConfig) ToWGTypesConfig(ctx context.Context) (*wgtypes.Config, error) {
	wgtypesConf := new(wgtypes.Config)

	wgtypesConf.ListenPort = wgConf.ListenPort

	var pk *wgtypes.Key
	var err error
	if wgConf.PrivateKey != "" || wgConf.PrivateKeyFrom != nil {
		pk, err = getKeyObj(ctx, wgConf.PrivateKey, wgConf.PrivateKeyFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key of interface %s: %w", wgConf.Name, err)
		}
	}

	if pk != nil {
		wgtypesConf.PrivateKey = pk
	}

	for _, peer := range wgConf.Peers {
		peercfg, err := peer.ToWGTypesPeer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer to wgtypes peer of interface %s: %w", wgConf.Name, err)
		}
		wgtypesConf.Peers = append(wgtypesConf.Peers, *peercfg)
	}

	return wgtypesConf, nil
}

func (wgConf *WireGuardConfig) Create(ctx context.Context) error {
	wgtypesConf, err := wgConf.ToWGTypesConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to convert wireguard config to wgtypes config: %w", err)
	}

	if wgtypesConf.PrivateKey == nil {
		keyObj, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("failed to generate private key: %w", err)
		}
		log.Printf("Randomly generated privatekey for interface %s", wgConf.Name)
		wgtypesConf.PrivateKey = &keyObj
	}

	if wgtypesConf.ListenPort == nil {
		listenPort := rand.Intn(65535-11024+1) + 11024
		wgtypesConf.ListenPort = &listenPort
		log.Printf("Randomly generated listen port for interface %s", wgConf.Name)
	}

	wgLink := &netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name: wgConf.Name,
		},
	}

	if wgConf.MTU != nil {
		wgLink.MTU = *wgConf.MTU
	}

	handle, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer handle.Close()

	var link netlink.Link = wgLink
	err = handle.LinkAdd(link)
	if err != nil {
		log.Printf("failed to add wireguard link %s: %v", wgConf.Name, err)
		link, err = handle.LinkByName(wgConf.Name)
		if err != nil {
			return fmt.Errorf("failed to get wireguard link %s: %w", wgConf.Name, err)
		}
	}

	wgCtrl, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("failed to new a wireguard controller: %w", err)
	}
	defer wgCtrl.Close()

	if err := wgCtrl.ConfigureDevice(wgConf.Name, *wgtypesConf); err != nil {
		return fmt.Errorf("failed to configure wireguard device: %w", err)
	}

	if err := handle.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set wireguard link up: %w", err)
	}

	err = pkgnetns.MoveLinkToNetns(ctx, wgConf, link)
	if err != nil {
		return fmt.Errorf("failed to move wireguard link to netns: %w", err)
	}

	return pkgnetns.WithNsHandle(ctx, wgConf, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(wgConf.Name)
		if err != nil {
			return fmt.Errorf("failed to get wireguard link: %w", err)
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set wireguard link up: %w", err)
		}

		for _, peer := range wgConf.Addresses {
			nlAddr, err := peer.ToNetlinkAddr()
			if err != nil {
				return fmt.Errorf("failed to convert address to netlink addr: %w", err)
			}
			err = handle.AddrAdd(link, nlAddr)
			if err != nil {
				return fmt.Errorf("failed to add address to wireguard link: %w", err)
			}
		}

		return nil
	})
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetType() string {
	return new(netlink.Wireguard).Type()
}

func parseSectionHeader(line string) string {
	if len(line) <= 2 {
		return ""
	}

	sectionName := strings.TrimRight(line[1:], "]")
	return strings.TrimSpace(sectionName)
}

func parsePeerSection(peerSection map[string]string) (*WireGuardPeerConfig, error) {
	wgPeerCfg := new(WireGuardPeerConfig)

	if val, ok := peerSection[WGINIKeyPublicKey]; ok {
		pkObj, err := wgtypes.ParseKey(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		wgPeerCfg.PublicKey = pkObj.String()
	}

	if val, ok := peerSection[WGINIKeyPresharedKey]; ok {
		if val != "" {
			pskObj, err := wgtypes.ParseKey(strings.TrimSpace(val))
			if err != nil {
				return nil, fmt.Errorf("failed to parse preshared key: %w", err)
			}
			wgPeerCfg.PresharedKey = pskObj.String()
		}
	}

	if val, ok := peerSection[WGINIKeyEndpoint]; ok {
		if val != "" {
			wgPeerCfg.Endpoint = &val
		}
	}

	if val, ok := peerSection[WGINIKeyAllowedIPs]; ok {
		if val != "" {
			allowedIPs := make([]string, 0)
			for _, allowedIP := range strings.Split(val, ",") {
				a := strings.TrimSpace(allowedIP)
				if a != "" {
					allowedIPs = append(allowedIPs, a)
				}
			}
			if len(allowedIPs) > 0 {
				wgPeerCfg.AllowedIPs = allowedIPs
			}
		}
	}

	if val, ok := peerSection[WGINIKeyPersistentKeepalive]; ok {
		if val != "" {
			pkl, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("failed to convert persistent keepalive to int: %w", err)
			}
			wgPeerCfg.PersistentKeepalive = &pkl
		}
	}

	return wgPeerCfg, nil
}

func eINIWGAdapterSecondPass(interfaceSection map[string]string, peerSections []map[string]string, additionals map[string]string) (*WireGuardConfig, error) {
	wgConf := new(WireGuardConfig)

	if val, ok := interfaceSection[WGINIKeyListenPort]; ok {
		listenPort, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("failed to convert listen port to int: %w", err)
		}
		wgConf.ListenPort = &listenPort
	}

	if val, ok := interfaceSection[WGINIKeyPrivateKey]; ok {
		pkObj, err := wgtypes.ParseKey(strings.TrimSpace(val))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		wgConf.PrivateKey = pkObj.String()
	}

	for _, peerSection := range peerSections {
		peerCfg, err := parsePeerSection(peerSection)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer section: %w", err)
		}
		wgConf.Peers = append(wgConf.Peers, *peerCfg)
	}

	for k, v := range additionals {
		if wgConf.Additionals == nil {
			wgConf.Additionals = make(map[string]string)
		}
		wgConf.Additionals[k] = v
	}

	ll, llok := wgConf.Additionals[WGAdditionalKeyLinkLocal]
	peerll, peerllok := wgConf.Additionals[WGAdditionalKeyPeerLinkLocal]
	if llok && peerllok && ll != "" && peerll != "" {
		// both have local side ip and peer side ip set
		// that is, both local side ip and peer side ip are present.
		addrconf := pkginterfacecommon.AddressConfig{
			Local: &ll,
			Peer:  &peerll,
		}
		if wgConf.Addresses == nil {
			wgConf.Addresses = make([]pkginterfacecommon.AddressConfig, 0)
		}
		wgConf.Addresses = append(wgConf.Addresses, addrconf)
	} else if llok || ll != "" {
		// only local side ip is present
		_, ipnet, err := net.ParseCIDR(ll)
		if err != nil {
			ip := net.ParseIP(ll)
			if ip == nil {
				return nil, fmt.Errorf("failed to parse local ip: %w", err)
			}

			fullMaskNet := pkgutils.WithFullMaskIPNet(ip)
			if fullMaskNet == nil {
				return nil, fmt.Errorf("failed to get full mask ip net: %w", err)
			}
			cidr := fullMaskNet.String()
			addrconf := pkginterfacecommon.AddressConfig{
				CIDR: &cidr,
			}
			wgConf.Addresses = append(wgConf.Addresses, addrconf)
		} else {
			cidr := ipnet.String()
			addrconf := pkginterfacecommon.AddressConfig{
				CIDR: &cidr,
			}
			wgConf.Addresses = append(wgConf.Addresses, addrconf)
		}
	} else {
		return nil, fmt.Errorf("missing local ip")
	}

	if vrf, vrfok := wgConf.Additionals[WGAdditionalKeyVRF]; vrfok && vrf != "" {
		wgConf.VRF = &vrf
	}

	return wgConf, nil
}

func (adapter *ExtendedINIWireGuardConfigAdapter) ToWireGuardConfig(raw []byte) (*WireGuardConfig, error) {
	filecontent := string(raw)
	lines := strings.Split(filecontent, "\n")

	var additionals map[string]string = nil

	// stage 1: parse additionals, and we will skip additional fields in the later stage(s)
	for _, line := range lines {
		trimed := strings.TrimSpace(line)
		if len(trimed) > 0 && trimed[0] == '#' {
			kvpairs := pkgutils.ParseKVPairs(":", trimed[1:])
			if len(kvpairs) > 0 {
				if additionals == nil {
					additionals = make(map[string]string)
				}
				for k, v := range kvpairs {
					additionals[k] = v
				}
			}
		}
	}

	type sectionobject struct {
		SectionName string
		SectionData map[string]string
	}

	sections := make([]sectionobject, 0)
	var currentSection *sectionobject = nil

	for lineIdx := 0; lineIdx < len(lines); lineIdx++ {
		trimed := strings.TrimSpace(lines[lineIdx])

		if trimed == "" {
			// skip empty lines
			continue
		}

		if trimed[0] == '#' {
			// as we already parsed additionals, we can simply skip them
			continue
		}

		if trimed[0] == '[' {
			sectionName := parseSectionHeader(trimed)
			sectionObj := sectionobject{
				SectionName: sectionName,
				SectionData: make(map[string]string),
			}
			currentSection = &sectionObj
			sections = append(sections, sectionObj)
			continue
		}

		if currentSection == nil {
			return nil, fmt.Errorf("no corresponding section found for line: %s", trimed)
		}

		kvpairs := pkgutils.ParseKVPairs("=", trimed)
		for k, v := range kvpairs {
			currentSection.SectionData[k] = v
		}
	}

	var interfaceSection *sectionobject = nil
	var peersSections []sectionobject = nil
	for _, section := range sections {
		if section.SectionName == "Interface" {
			interfaceSection = &section
			continue
		}
		if section.SectionName == "Peer" {
			peersSections = append(peersSections, section)
			continue
		}
	}

	peerSectionMaps := make([]map[string]string, 0)
	for _, section := range peersSections {
		peerSectionMaps = append(peerSectionMaps, section.SectionData)
	}

	if interfaceSection == nil {
		return nil, fmt.Errorf("no [Interface] section found, thus it's not a valid WireGuard ini config")
	}

	return eINIWGAdapterSecondPass(interfaceSection.SectionData, peerSectionMaps, additionals)
}

func (wgConfig *WireGuardConfig) IsSoftDeleted() bool {
	return wgConfig.Deleted
}

func (wgConfig *WireGuardConfig) SetNodeAndResourceID(nodeName string) error {
	if nodeName == "" {
		return fmt.Errorf("node name is required")
	}
	if wgConfig.Node == nil || *wgConfig.Node == "" {
		wgConfig.Node = pkgutils.StringPtr(nodeName)
	}

	if wgConfig.ResourceId == nil || *wgConfig.ResourceId == "" {
		if wgConfig.Name == "" {
			return fmt.Errorf("interface name is required")
		}
		wgConfig.ResourceId = pkgutils.StringPtr(fmt.Sprintf("%s-%s", nodeName, wgConfig.Name))
	}

	return nil
}

func (wgConfig *WireGuardConfig) GetResourceID() (string, error) {
	if wgConfig.ResourceId == nil || *wgConfig.ResourceId == "" {
		return "", fmt.Errorf("resource id is not set")
	}
	return *wgConfig.ResourceId, nil
}

// A WireGuardConfig is also an implementation of NetNsAwareResource interface
func (wgConfig *WireGuardConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return wgConfig.Container.GetNetNsInfo(ctx)
}
