package bgp

import (
	"fmt"
)

func (afConf *MPBGPAddressFamilyConfig) ToCLICommands(bgpConf *BGPConfig) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("address-family %s %s", afConf.AFI, afConf.SAFI))

	for _, nb := range afConf.Activate {
		cmds = append(cmds, fmt.Sprintf("neighbor %s activate", nb))
	}

	for _, network := range afConf.Networks {
		cmds = append(cmds, fmt.Sprintf("network %s", network))
	}

	if afConf.AdvertiseAllVNI != nil {
		cmds = append(cmds, "advertise-all-vni")
	}

	if afConf.AdvertiseSVIIP != nil {
		cmds = append(cmds, "advertise-svi-ip")
	}

	if afConf.RouteReflectorClientNeighbors != nil {
		for _, nb := range afConf.RouteReflectorClientNeighbors {
			cmds = append(cmds, fmt.Sprintf("neighbor %s route-reflector-client", nb))
		}
	}

	for _, routeMap := range afConf.RouteMaps {
		cmds = append(cmds, fmt.Sprintf("neighbor %s route-map %s %s", routeMap.Peer, routeMap.Name, routeMap.Direction))
	}

	cmds = append(cmds, "exit-address-family")

	return cmds
}

func (bgpNeighborGroupConfig *BGPNeighborGroupConfig) ToCLICommands(groupName string) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group", groupName))
	cmds = append(cmds, fmt.Sprintf("neighbor %s remote-as %d", groupName, bgpNeighborGroupConfig.ASN))
	if bgpNeighborGroupConfig.UpdateSource != nil && *bgpNeighborGroupConfig.UpdateSource != "" {
		cmds = append(cmds, fmt.Sprintf("neighbor %s update-source %s", groupName, *bgpNeighborGroupConfig.UpdateSource))
	}

	for _, capability := range bgpNeighborGroupConfig.Capabilities {
		cmds = append(cmds, fmt.Sprintf("neighbor %s capability %s", groupName, capability))
	}

	for _, peer := range bgpNeighborGroupConfig.Peers {
		cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group %s", peer, groupName))
	}

	if bgpNeighborGroupConfig.ListenRange != nil && *bgpNeighborGroupConfig.ListenRange != "" {
		cmds = append(cmds, fmt.Sprintf("bgp listen range %s peer-group %s", *bgpNeighborGroupConfig.ListenRange, groupName))
	}

	if bgpNeighborGroupConfig.EBGPMultihop != nil && *bgpNeighborGroupConfig.EBGPMultihop {
		cmds = append(cmds, fmt.Sprintf("neighbor %s ebgp-multihop", groupName))
	}

	return cmds
}

func (rpkiConf *BGPRPKIConfig) ToCLICommands() []string {
	cmds := make([]string, 0)

	if rpkiConf.VRF != nil {
		cmds = append(cmds, fmt.Sprintf("vrf %s", *rpkiConf.VRF))
	}

	cmds = append(cmds, "rpki")
	cmds = append(cmds, fmt.Sprintf("rpki polling-period %d", rpkiConf.PollingPeriod))
	cmds = append(cmds, fmt.Sprintf("rpki expire-interval %d", rpkiConf.ExpireInterval))
	cmds = append(cmds, fmt.Sprintf("rpki retry-interval %d", rpkiConf.RetryInterval))

	for _, rtrServer := range rpkiConf.RTRServers {
		cmds = append(cmds, fmt.Sprintf("rpki cache tcp %s %d preference %d", rtrServer.RTRHost, rtrServer.RTRPort, rtrServer.RTRPreference))
	}

	cmds = append(cmds, "exit")

	if rpkiConf.VRF != nil {
		cmds = append(cmds, "exit-vrf")
	}

	return cmds
}

func (bgpConf *BGPConfig) ToCLICommands() []string {
	cmds := make([]string, 0)
	cmds = append(cmds, fmt.Sprintf("router bgp %d vrf %s", bgpConf.ASN, bgpConf.VRF))
	cmds = append(cmds, fmt.Sprintf("bgp router-id %s", bgpConf.RouterID))

	if bgpConf.ClusterID != nil && *bgpConf.ClusterID != "" {
		cmds = append(cmds, fmt.Sprintf("bgp cluster-id %s", *bgpConf.ClusterID))
	}

	if bgpConf.NoIPv4Unicast {
		cmds = append(cmds, "no bgp default ipv4-unicast")
	}

	if bgpConf.NoIPv6AutoRA != nil && *bgpConf.NoIPv6AutoRA {
		cmds = append(cmds, "no bgp ipv6-auto-ra")
	}

	if bgpConf.NoNetworkImportCheck != nil && *bgpConf.NoNetworkImportCheck {
		cmds = append(cmds, "bgp network import-check")
	}

	if bgpConf.DisableEBGPConnectedRouteCheck != nil && *bgpConf.DisableEBGPConnectedRouteCheck {
		cmds = append(cmds, "bgp disable-ebgp-connected-route-check")
	}

	if bgpConf.LogNeighborChanges != nil && *bgpConf.LogNeighborChanges {
		cmds = append(cmds, "bgp log-neighbor-changes")
	}

	for _, linklocalPeer := range bgpConf.LinkLocalPeers {
		nb := linklocalPeer.PeerLinkLocalAddress

		if linklocalPeer.Unnumbered != nil && *linklocalPeer.Unnumbered {
			nb = linklocalPeer.InterfaceName
			cmds = append(cmds, fmt.Sprintf("neighbor %s interface remote-as %d", nb, linklocalPeer.PeerASN))
		} else {
			cmds = append(cmds, fmt.Sprintf("neighbor %s remote-as %d", linklocalPeer.PeerLinkLocalAddress, linklocalPeer.PeerASN))
			cmds = append(cmds, fmt.Sprintf("neighbor %s interface %s", linklocalPeer.PeerLinkLocalAddress, linklocalPeer.InterfaceName))
		}

		for _, capability := range linklocalPeer.Capabilities {
			cmds = append(cmds, fmt.Sprintf("neighbor %s capability %s", nb, capability))
		}
		if linklocalPeer.UpdateSource != nil && *linklocalPeer.UpdateSource != "" {
			cmds = append(cmds, fmt.Sprintf("neighbor %s update-source %s", nb, *linklocalPeer.UpdateSource))
		}

		if linklocalPeer.EBGPMultihop != nil && *linklocalPeer.EBGPMultihop {
			cmds = append(cmds, fmt.Sprintf("neighbor %s ebgp-multihop", nb))
		}
	}

	if bgpConf.PeerGroups != nil {
		for groupName, groupConfig := range bgpConf.PeerGroups {
			cmds = append(cmds, groupConfig.ToCLICommands(groupName)...)
		}
	}

	if bgpConf.AddressFamilies != nil {
		for _, afConf := range bgpConf.AddressFamilies {
			cmds = append(cmds, afConf.ToCLICommands(bgpConf)...)
		}
	}
	for _, nb := range bgpConf.NeighborRPKIStrict {
		cmds = append(cmds, fmt.Sprintf("neighbor %s rpki strict", nb))
	}

	cmds = append(cmds, "exit")

	return cmds
}

func (routeMapConf *RouteMapConfig) ToCLICommands() []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("route-map %s %s %d", routeMapConf.Name, routeMapConf.Policy, routeMapConf.Order))

	cmds = append(cmds, routeMapConf.MatchCommands...)
	cmds = append(cmds, routeMapConf.SetCommands...)
	cmds = append(cmds, routeMapConf.CallCommands...)
	cmds = append(cmds, routeMapConf.ExitActionCommands...)

	cmds = append(cmds, "exit")

	return cmds
}
