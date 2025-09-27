package bgp

type MPBGPAddressFamilyConfig struct {
	AFI  string `yaml:"afi" json:"afi"`
	SAFI string `yaml:"safi" json:"safi"`

	// following fields are only supported in (afi=l2vpn, safi=evpn)
	AdvertiseAllVNI *bool `yaml:"advertise_all_vni" json:"advertise_all_vni"`
	AdvertiseSVIIP  *bool `yaml:"advertise_svi_ip" json:"advertise_svi_ip"`
}

type BGPPeerConfig struct {
	Address string `yaml:"address" json:"address"`
}

type BGPNeighborGroupConfig struct {
	Capabilities []string        `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Peers        []BGPPeerConfig `yaml:"peers,omitempty" json:"peers,omitempty"`
	ASN          int             `yaml:"asn,omitempty" json:"asn,omitempty"`
}

type BGPConfig struct {
	// Currently only 'default' vrf is supported
	VRF             string                     `yaml:"vrf" json:"vrf"`
	ASN             int                        `yaml:"asn" json:"asn"`
	RouterID        string                     `yaml:"router_id" json:"router_id"`
	NoIPv4Unicast   bool                       `yaml:"no_ipv4_unicast" json:"no_ipv4_unicast"`
	AddressFamilies []MPBGPAddressFamilyConfig `yaml:"address_families" json:"address_families"`

	// key is the group name
	Neighbors map[string]BGPNeighborGroupConfig `yaml:"neighbors" json:"neighbors"`
}
