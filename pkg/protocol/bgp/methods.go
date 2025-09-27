package bgp

import "fmt"

func (afConf *MPBGPAddressFamilyConfig) ToCLICommands(bgpConf *BGPConfig) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("address-family %s %s", afConf.AFI, afConf.SAFI))

	if bgpConf.Neighbors != nil {
		for groupName := range bgpConf.Neighbors {
			cmds = append(cmds, fmt.Sprintf("neighbor %s activate", groupName))
		}
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
			cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group %s", peer.Address, groupName))
		}
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

	cmds = append(cmds, "exit")

	return cmds
}
