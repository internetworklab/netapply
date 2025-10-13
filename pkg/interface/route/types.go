package route

type RouteConfig struct {
	Name    string `yaml:"name" json:"name"`
	TableId *int   `yaml:"table_id,omitempty" json:"table_id,omitempty"`

	// When TableId and VRF are both specified, TableId will take precedence over VRF
	// If they are both nil, the default VRF will be used
	VRF *string `yaml:"vrf,omitempty" json:"vrf,omitempty"`

	ContainerName *string `yaml:"container_name,omitempty" json:"container_name,omitempty"`

	// Destination is a CIDR string
	Destionation string `yaml:"destionation" json:"destionation"`

	NextHop string `yaml:"next_hop,omitempty" json:"next_hop,omitempty"`

	NextHopInterface *string `yaml:"next_hop_interface,omitempty" json:"next_hop_interface,omitempty"`
}

type RouteConfigurationList []RouteConfig
