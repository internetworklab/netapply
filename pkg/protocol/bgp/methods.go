package bgp

import "fmt"

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

	cmds = append(cmds, "exit-address-family")

	return cmds
}

func (bgpNeighborGroupConfig *BGPNeighborGroupConfig) ToCLICommands(groupName string) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group", groupName))
	cmds = append(cmds, fmt.Sprintf("neighbor %s remote-as %d", groupName, bgpNeighborGroupConfig.ASN))

	if bgpNeighborGroupConfig.Capabilities != nil {
		for _, capability := range bgpNeighborGroupConfig.Capabilities {
			cmds = append(cmds, fmt.Sprintf("neighbor %s capability %s", groupName, capability))
		}
	}

	if bgpNeighborGroupConfig.Peers != nil {
		for _, peer := range bgpNeighborGroupConfig.Peers {
			cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group %s", peer, groupName))
		}
	}

	for _, routeMap := range bgpNeighborGroupConfig.RouteMaps {
		cmds = append(
			cmds,
			fmt.Sprintf("neighbor %s route-map %s %s", groupName, routeMap.Name, routeMap.Direction),
		)
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

	if bgpConf.NoIPv4Unicast {
		cmds = append(cmds, "no bgp default ipv4-unicast")
	}

	if bgpConf.Neighbors != nil {
		for groupName, groupConfig := range bgpConf.Neighbors {
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
