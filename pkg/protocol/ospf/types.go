package ospf

type OSPFConfig struct {
	// Currently only 'default' vrf is supported
	VRF        string                `yaml:"vrf" json:"vrf"`
	RouterID   string                `yaml:"router_id" json:"router_id"`
	Interfaces []OSPFInterfaceConfig `yaml:"interfaces" json:"interfaces"`
}

type OSPFInterfaceConfig struct {
	Name    string  `yaml:"name" json:"name"`
	Area    string  `yaml:"area" json:"area"`
	Passive *bool   `yaml:"passive" json:"passive"`
	Network *string `yaml:"network" json:"network"`
}
