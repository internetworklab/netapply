package bgp

import "fmt"

func (afConf *MPBGPAddressFamilyConfig) ToCLICommands(bgpConf *BGPConfig) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("address-family %s %s", afConf.AFI, afConf.SAFI))

	if bgpConf.Neighbors != nil && afConf.Activate != nil && *afConf.Activate {
		for groupName := range bgpConf.Neighbors {
			cmds = append(cmds, fmt.Sprintf("neighbor %s activate", groupName))
		}
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

	return cmds
}

func (rpkiConf *BGPRPKIConfig) ToCLICommands() []string {
	cmds := make([]string, 0)
	cmds = append(cmds, fmt.Sprintf("rpki polling-period %d", rpkiConf.PollingPeriod))
	cmds = append(cmds, fmt.Sprintf("rpki expire-interval %d", rpkiConf.ExpireInterval))
	cmds = append(cmds, fmt.Sprintf("rpki retry-interval %d", rpkiConf.RetryInterval))
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

	if bgpConf.RPKI {
		cmds = append(cmds, "rpki enable")
		if bgpConf.RPKIConfig != nil {
			cmds = append(cmds, bgpConf.RPKIConfig.ToCLICommands()...)
		}
	}

	cmds = append(cmds, "exit")

	return cmds
}
