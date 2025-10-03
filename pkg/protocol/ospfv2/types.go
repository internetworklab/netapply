package ospfv2

type OSPFV2Config struct {
	VRF           string                  `yaml:"vrf" json:"vrf"`
	RouterID      string                  `yaml:"router_id" json:"router_id"`
	Interfaces    []OSPFV2InterfaceConfig `yaml:"interfaces" json:"interfaces"`
	NBMANeighbors []string                `yaml:"nbma_neighbors" json:"nbma_neighbors"`
}

type OSPFV2InterfaceConfig struct {
	Name    string  `yaml:"name" json:"name"`
	Area    string  `yaml:"area" json:"area"`
	Passive *bool   `yaml:"passive" json:"passive"`
	Network *string `yaml:"network" json:"network"`
}
