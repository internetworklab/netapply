package wireguard

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
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

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetContainerName() *string {
	return wgInterfaceChangeSet.ContainerName
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetInterfaceName() string {
	return wgInterfaceChangeSet.InterfaceName
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) HasUpdates() bool {
	if wgInterfaceChangeSet == nil {
		return false
	}

	if wgInterfaceChangeSet.PrivateKeyToSet != nil {
		return true
	}

	if wgInterfaceChangeSet.MTUToSet != nil {
		return true
	}

	if wgInterfaceChangeSet.ListenPortToSet != nil {
		return true
	}

	if len(wgInterfaceChangeSet.PeersToRemove) > 0 {
		return true
	}

	if len(wgInterfaceChangeSet.PeersToAdd) > 0 {
		return true
	}

	if len(wgInterfaceChangeSet.AddressesToAdd) > 0 {
		return true
	}

	if len(wgInterfaceChangeSet.AddressesToRemove) > 0 {
		return true
	}

	return false
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) Apply(ctx context.Context) error {
	if wgInterfaceChangeSet == nil {
		return nil
	}

	containerName := wgInterfaceChangeSet.ContainerName

	if wgInterfaceChangeSet.PrivateKeyToSet != nil || wgInterfaceChangeSet.ListenPortToSet != nil || wgInterfaceChangeSet.PeersToRemove != nil || wgInterfaceChangeSet.PeersToAdd != nil {
		err := pkgdocker.WithNetnsWGCli(ctx, containerName, func(wgCtrl *wgctrl.Client) error {
			currentConfig, err := wgCtrl.Device(wgInterfaceChangeSet.InterfaceName)
			if err != nil {
				return fmt.Errorf("failed to get wireguard device: %w", err)
			}

			if currentConfig == nil {
				return fmt.Errorf("failed to get wireguard device: %s in %s", wgInterfaceChangeSet.InterfaceName, pkgdocker.GetContainerDisplayName(wgInterfaceChangeSet.ContainerName))
			}

			if wgInterfaceChangeSet.PrivateKeyToSet != nil {
				patchConfig := new(wgtypes.Config)
				patchConfig.PrivateKey = wgInterfaceChangeSet.PrivateKeyToSet
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			if wgInterfaceChangeSet.ListenPortToSet != nil {
				patchConfig := new(wgtypes.Config)
				patchConfig.ListenPort = wgInterfaceChangeSet.ListenPortToSet
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
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
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			for _, p := range wgInterfaceChangeSet.PeersToAdd {
				patchConfig := new(wgtypes.Config)
				patchConfig.Peers = make([]wgtypes.PeerConfig, 0)
				patchConfig.ReplacePeers = false
				patchConfig.Peers = append(patchConfig.Peers, p)
				if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
					return fmt.Errorf("failed to patch wireguard config: %w", err)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to apply wireguard config: %w", err)
		}
	}

	if wgInterfaceChangeSet.MTUToSet != nil || wgInterfaceChangeSet.ListenPortToSet != nil {
		err := pkgdocker.WithNsHandle(ctx, containerName, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(wgInterfaceChangeSet.InterfaceName)
			if err != nil {
				return fmt.Errorf("failed to get wireguard link: %w", err)
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
				if err := handle.AddrAdd(link, addr); err != nil {
					return fmt.Errorf("failed to add wireguard link address: %w", err)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to apply wireguard netlink config: %w", err)
		}
	}

	return nil
}

func (wgConf *WireGuardConfig) GetInterfaceName() string {
	return wgConf.Name
}

func (wgConf *WireGuardConfig) GetContainerName() *string {
	return wgConf.ContainerName
}

// returns: (added, removed)
func checkWGPeersDifference(specPeers []wgtypes.PeerConfig, currentPeers []*wgtypes.Peer, endpointAddrCheckMask map[string]bool) (map[string]wgtypes.PeerConfig, map[string]*wgtypes.Peer) {

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

		if shouldCheckEndpoint, ok := endpointAddrCheckMask[k]; ok && shouldCheckEndpoint {
			if pkgutils.IsUDPAddrNotEqu(spec.Endpoint, peer.Endpoint) {
				peersToRemove[k] = peer
				peersToAdd[k] = spec
			}
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
	changeSet.ContainerName = wgConf.ContainerName
	changeSet.InterfaceName = wgConf.Name

	err := pkgdocker.WithNetnsWGCli(ctx, wgConf.ContainerName, func(wgCtrl *wgctrl.Client) error {
		currentConfig, err := wgCtrl.Device(wgConf.Name)
		if err != nil {
			return fmt.Errorf("failed to get wireguard device: %w", err)
		}

		if currentConfig == nil {
			return fmt.Errorf("failed to get wireguard device: %s in %s", wgConf.Name, pkgdocker.GetContainerDisplayName(wgConf.ContainerName))
		}

		endpointCheckingMask := make(map[string]bool)
		specPeerConfigs := make([]wgtypes.PeerConfig, 0)
		for _, peer := range wgConf.Peers {
			peercfg, err := peer.ToWGTypesPeer()
			if peer.ForceRecheckEndpoint != nil && *peer.ForceRecheckEndpoint {
				endpointCheckingMask[peer.PublicKey] = true
			}

			if err != nil {
				return fmt.Errorf("failed to convert peer to wgtypes peer: %w", err)
			}
			specPeerConfigs = append(specPeerConfigs, *peercfg)
		}

		currPeers := make([]*wgtypes.Peer, 0)
		for _, peer := range currentConfig.Peers {
			currPeers = append(currPeers, &peer)
		}

		addedPeers, removedPeers := checkWGPeersDifference(specPeerConfigs, currPeers, endpointCheckingMask)
		changeSet.PeersToAdd = addedPeers
		changeSet.PeersToRemove = removedPeers

		wgtypesConf, err := wgConf.ToWGTypesConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to convert wireguard config to wgtypes config: %w", err)
		}

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

	err = pkgdocker.WithNsHandle(ctx, wgConf.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(wgConf.Name)
		if err != nil {
			return fmt.Errorf("failed to get wireguard link: %w", err)
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

func (wgPeerConfig *WireGuardPeerConfig) ToWGTypesPeer() (*wgtypes.PeerConfig, error) {
	peercfg := new(wgtypes.PeerConfig)

	pk, err := wgtypes.ParseKey(wgPeerConfig.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	peercfg.PublicKey = pk

	if wgPeerConfig.Endpoint != nil {
		udpAddr, err := net.ResolveUDPAddr("udp", *wgPeerConfig.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve udp address: %w", err)
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

func getPrivKey(ctx context.Context, pkB64 string, pkURL *string) (*wgtypes.Key, error) {
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
		return getPrivKey(ctx, string(pkContent), nil)
	}
	return nil, fmt.Errorf("private key is not set")
}

func (wgConf *WireGuardConfig) ToWGTypesConfig(ctx context.Context) (*wgtypes.Config, error) {
	wgtypesConf := new(wgtypes.Config)

	wgtypesConf.ListenPort = wgConf.ListenPort

	pk, err := getPrivKey(ctx, wgConf.PrivateKey, wgConf.PrivateKeyFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	wgtypesConf.PrivateKey = pk

	for _, peer := range wgConf.Peers {
		peercfg, err := peer.ToWGTypesPeer()
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer to wgtypes peer: %w", err)
		}
		wgtypesConf.Peers = append(wgtypesConf.Peers, *peercfg)
	}

	return wgtypesConf, nil
}

func (wgConf *WireGuardConfig) Create(ctx context.Context) error {
	return pkgdocker.WithNsHandle(ctx, nil, func(handle *netlink.Handle) error {
		link := &netlink.Wireguard{
			LinkAttrs: netlink.LinkAttrs{
				Name: wgConf.Name,
			},
		}

		if wgConf.MTU != nil {
			link.MTU = *wgConf.MTU
		}

		if err := handle.LinkAdd(link); err != nil {
			return fmt.Errorf("failed to add wireguard link: %w", err)
		}

		wgCtrl, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to create wireguard controller: %w", err)
		}
		defer wgCtrl.Close()

		wgtypesConf, err := wgConf.ToWGTypesConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to convert wireguard config to wgtypes config: %w", err)
		}

		if err := wgCtrl.ConfigureDevice(wgConf.Name, *wgtypesConf); err != nil {
			return fmt.Errorf("failed to configure wireguard device: %w", err)
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set wireguard link up: %w", err)
		}

		if wgConf.ContainerName != nil {
			cli, err := pkgutils.DockerCliFromCtx(ctx)
			if err != nil {
				return fmt.Errorf("failed to get docker cli from context: %w", err)
			}

			pidPtr, err := pkgdocker.GetContainerNSPid(ctx, cli, *wgConf.ContainerName)
			if err != nil {
				return fmt.Errorf("failed to get container ns pid: %w", err)
			}
			if pidPtr != nil {
				if err := netlink.LinkSetNsPid(link, int(*pidPtr)); err != nil {
					return fmt.Errorf("failed to set wireguard link ns pid: %w", err)
				}
			}
		}

		return pkgdocker.WithNsHandle(ctx, wgConf.ContainerName, func(handle *netlink.Handle) error {
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
	})
}

// Scan containers specified for any reconciliation clues.
func (wgList WireGuardConfigurationList) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {
	wgty := new(netlink.Wireguard).Type()
	provisionerList := make([]pkgreconcile.InterfaceProvisioner, 0)
	for _, wg := range wgList {
		provisionerList = append(provisionerList, &wg)
	}
	return pkgreconcile.DetectChangesFromProvisionerList(ctx, provisionerList, wgty, containers)
}
