package bgp

type AddressFamilyIndicatorName string

const (
	AFIIPv4  AddressFamilyIndicatorName = "ipv4"
	AFIIPv6  AddressFamilyIndicatorName = "ipv6"
	AFIL2VPN AddressFamilyIndicatorName = "l2vpn"
)

type SubsequentAddressFamilyIndicatorName string

const (
	SAFIEVPN      SubsequentAddressFamilyIndicatorName = "evpn"
	SAFIUnicast   SubsequentAddressFamilyIndicatorName = "unicast"
	SAFIMulticast SubsequentAddressFamilyIndicatorName = "multicast"
)

type MPBGPAddressFamilyConfig struct {
	AFI  AddressFamilyIndicatorName           `yaml:"afi" json:"afi"`
	SAFI SubsequentAddressFamilyIndicatorName `yaml:"safi" json:"safi"`

	// following fields are only supported in (afi=l2vpn, safi=evpn)
	AdvertiseAllVNI *bool `yaml:"advertise_all_vni" json:"advertise_all_vni"`
	AdvertiseSVIIP  *bool `yaml:"advertise_svi_ip" json:"advertise_svi_ip"`

	// Networks to advertise, e.g.: ["10.3.64.0/24, 10.8.1.0/16"]
	Networks []string `yaml:"networks,omitempty" json:"networks,omitempty"`

	// This configuration modifies whether to enable an address family for a specific neighbor.
	// By default only the IPv4 unicast address family is enabled.
	Activate *bool `yaml:"activate" json:"activate"`
}

type BGPNeighborGroupConfig struct {
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`

	// Addresses of the peers in the group
	Peers []string `yaml:"peers,omitempty" json:"peers,omitempty"`
	ASN   int      `yaml:"asn,omitempty" json:"asn,omitempty"`

	RPKIStrict *bool `yaml:"rpki_strict,omitempty" json:"rpki_strict,omitempty"`
}

type BGPRPKIRTRConfig struct {
	RTRHost       string `yaml:"rtr_host" json:"rtr_host"`
	RTRPort       int    `yaml:"rtr_port" json:"rtr_port"`
	RTRPreference int    `yaml:"rtr_preference" json:"rtr_preference"`
}

type BGPRPKIConfig struct {
	// 1 - 3600 seconds, the default is 300 seconds
	PollingPeriod *int `yaml:"polling_period,omitempty" json:"polling_period,omitempty"`

	// 600-172800, the default is 7200 seconds
	ExpireInterval *int `yaml:"expire_interval,omitempty" json:"expire_interval,omitempty"`

	// 1-7200, the default is 600 seconds
	RetryInterval *int `yaml:"retry_interval,omitempty" json:"retry_interval,omitempty"`

	RTRServers []BGPRPKIRTRConfig `yaml:"rtr_servers,omitempty" json:"rtr_servers,omitempty"`
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

	RPKI       bool           `yaml:"rpki" json:"rpki"`
	RPKIConfig *BGPRPKIConfig `yaml:"rpki_config,omitempty" json:"rpki_config,omitempty"`
}
