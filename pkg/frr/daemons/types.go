package daemons

type FRREnabledDaemonsConfig struct {
	EnableBGPd bool `yaml:"bgpd,omitempty" json:"bgpd,omitempty"`

	// i.e. OSPFv2
	EnableOSPFd bool `yaml:"ospfd,omitempty" json:"ospfd,omitempty"`

	// i.e. OSPFv3
	EnableOSPF6d bool `yaml:"ospf6d,omitempty" json:"ospf6d,omitempty"`

	EnableRIPd    bool `yaml:"ripd,omitempty" json:"ripd,omitempty"`
	EnableRIPNGd  bool `yaml:"ripngd,omitempty" json:"ripngd,omitempty"`
	EnableISISd   bool `yaml:"isisd,omitempty" json:"isisd,omitempty"`
	EnablePIMd    bool `yaml:"pimd,omitempty" json:"pimd,omitempty"`
	EnablePIM6d   bool `yaml:"pim6d,omitempty" json:"pim6d,omitempty"`
	EnableLDPd    bool `yaml:"ldpd,omitempty" json:"ldpd,omitempty"`
	EnableNHRPd   bool `yaml:"nhrpd,omitempty" json:"nhrpd,omitempty"`
	EnableEIGRPd  bool `yaml:"eigrpd,omitempty" json:"eigrpd,omitempty"`
	EnableBabeld  bool `yaml:"babeld,omitempty" json:"babeld,omitempty"`
	EnableSharpd  bool `yaml:"sharpd,omitempty" json:"sharpd,omitempty"`
	EnablePBRd    bool `yaml:"pbrd,omitempty" json:"pbrd,omitempty"`
	EnableBFDDd   bool `yaml:"bfdd,omitempty" json:"bfdd,omitempty"`
	EnableFabricd bool `yaml:"fabricd,omitempty" json:"fabricd,omitempty"`
	EnableVRRPd   bool `yaml:"vrrpd,omitempty" json:"vrrpd,omitempty"`
	EnablePathd   bool `yaml:"pathd,omitempty" json:"pathd,omitempty"`
}

type FRRPerDaemonCLIArgumentsConfig struct {
	ZebraOptions   []string `yaml:"zebra_options,omitempty" json:"zebra_options,omitempty"`
	MGMTdOptions   []string `yaml:"mgmtd_options,omitempty" json:"mgmtd_options,omitempty"`
	BGPdOptions    []string `yaml:"bgpd_options,omitempty" json:"bgpd_options,omitempty"`
	OSPFdOptions   []string `yaml:"ospfd_options,omitempty" json:"ospfd_options,omitempty"`
	OSPF6dOptions  []string `yaml:"ospf6d_options,omitempty" json:"ospf6d_options,omitempty"`
	RIPdOptions    []string `yaml:"ripd_options,omitempty" json:"ripd_options,omitempty"`
	RIPNGdOptions  []string `yaml:"ripngd_options,omitempty" json:"ripngd_options,omitempty"`
	ISISdOptions   []string `yaml:"isisd_options,omitempty" json:"isisd_options,omitempty"`
	PIMdOptions    []string `yaml:"pimd_options,omitempty" json:"pimd_options,omitempty"`
	PIM6dOptions   []string `yaml:"pim6d_options,omitempty" json:"pim6d_options,omitempty"`
	LDPdOptions    []string `yaml:"ldpd_options,omitempty" json:"ldpd_options,omitempty"`
	NHRPdOptions   []string `yaml:"nhrpd_options,omitempty" json:"nhrpd_options,omitempty"`
	EIGRPdOptions  []string `yaml:"eigrpd_options,omitempty" json:"eigrpd_options,omitempty"`
	BabeldOptions  []string `yaml:"babeld_options,omitempty" json:"babeld_options,omitempty"`
	SharpdOptions  []string `yaml:"sharpd_options,omitempty" json:"sharpd_options,omitempty"`
	PBRdOptions    []string `yaml:"pbrd_options,omitempty" json:"pbrd_options,omitempty"`
	StaticdOptions []string `yaml:"staticd_options,omitempty" json:"staticd_options,omitempty"`
	BFDDdOptions   []string `yaml:"bfdd_options,omitempty" json:"bfdd_options,omitempty"`
	FabricdOptions []string `yaml:"fabricd_options,omitempty" json:"fabricd_options,omitempty"`
	VRRPdOptions   []string `yaml:"vrrpd_options,omitempty" json:"vrrpd_options,omitempty"`
	PathdOptions   []string `yaml:"pathd_options,omitempty" json:"pathd_options,omitempty"`
}
