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
	Activate []string `yaml:"activate,omitempty" json:"activate,omitempty"`

	// Useful in BGP Route Reflector, treat peer as the client of BGP RR.
	RouteReflectorClientNeighbors []string `yaml:"route_reflector_client,omitempty" json:"route_reflector_client,omitempty"`
}

type RouteMapDirection string

const (
	RouteMapDirectionIn  RouteMapDirection = "in"
	RouteMapDirectionOut RouteMapDirection = "out"
)

type BGPNeighborRouteMapApply struct {
	// Name of the route-map to apply to the neighbor
	Name string `yaml:"name" json:"name"`

	// Direction of the route-map to apply to the neighbor
	Direction RouteMapDirection `yaml:"direction" json:"direction"`
}

type BGPNeighborGroupConfig struct {
	Capabilities []string                   `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	RouteMaps    []BGPNeighborRouteMapApply `yaml:"route_maps,omitempty" json:"route_maps,omitempty"`

	// Addresses of the peers in the group
	Peers        []string `yaml:"peers,omitempty" json:"peers,omitempty"`
	ASN          int      `yaml:"asn,omitempty" json:"asn,omitempty"`
	UpdateSource *string  `yaml:"update_source,omitempty" json:"update_source,omitempty"`
	ListenRange  *string  `yaml:"listen_range,omitempty" json:"listen_range,omitempty"`
}

type BGPRPKIRTRConfig struct {
	RTRHost       string `yaml:"rtr_host" json:"rtr_host"`
	RTRPort       int    `yaml:"rtr_port" json:"rtr_port"`
	RTRPreference int    `yaml:"rtr_preference" json:"rtr_preference"`
}

type BGPRPKIConfig struct {
	VRF *string `yaml:"vrf,omitempty" json:"vrf,omitempty"`

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
	ClusterID       *string                    `yaml:"cluster_id,omitempty" json:"cluster_id,omitempty"`
	NoIPv4Unicast   bool                       `yaml:"no_ipv4_unicast" json:"no_ipv4_unicast"`
	AddressFamilies []MPBGPAddressFamilyConfig `yaml:"address_families" json:"address_families"`

	// key is the group name
	Neighbors map[string]BGPNeighborGroupConfig `yaml:"neighbors" json:"neighbors"`

	NeighborRPKIStrict []string `yaml:"neighbor_rpki_strict,omitempty" json:"neighbor_rpki_strict,omitempty"`
	LogNeighborChanges *bool `yaml:"log_neighbor_changes,omitempty" json:"log_neighbor_changes,omitempty"`
}

type RouteMapPolicy string

const (
	// If the entry matches, then carry out the Set Actions.
	RouteMapPolicyPermit RouteMapPolicy = "permit"
	//  If the entry matches, then finish processing the route-map and deny the route (return deny).
	RouteMapPolicyDeny RouteMapPolicy = "deny"
)

type RouteMapConfig struct {
	Name string `yaml:"name" json:"name"`

	// This specifies the policy implied if the Matching Conditions are met or not met, and which actions of the route-map are to be taken, if any.
	Policy RouteMapPolicy `yaml:"policy" json:"policy"`
	Order  int            `yaml:"order" json:"order"`

	MatchCommands      []string `yaml:"match_commands,omitempty" json:"match_commands,omitempty"`
	SetCommands        []string `yaml:"set_commands,omitempty" json:"set_commands,omitempty"`
	CallCommands       []string `yaml:"call_commands,omitempty" json:"call_commands,omitempty"`
	ExitActionCommands []string `yaml:"exit_action_commands,omitempty" json:"exit_action_commands,omitempty"`
}
