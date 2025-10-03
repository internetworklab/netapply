package models

import (
	pkgfrrcontainer "github.com/internetworklab/netapply/pkg/frr/container"
	pkginterfacebridge "github.com/internetworklab/netapply/pkg/interface/bridge"
	pkginterfacedummy "github.com/internetworklab/netapply/pkg/interface/dummy"
	pkginterfaceveth "github.com/internetworklab/netapply/pkg/interface/veth"
	pkginterfacevxlan "github.com/internetworklab/netapply/pkg/interface/vxlan"
	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgopenvpn2 "github.com/internetworklab/netapply/pkg/openvpn2"
	pkgprotocolbgp "github.com/internetworklab/netapply/pkg/protocol/bgp"
	pkgprotocolospfv2 "github.com/internetworklab/netapply/pkg/protocol/ospfv2"
)

type GlobalConfig struct {
	Nodes map[string]NodeConfig `yaml:"nodes" json:"nodes"`
}

type ControlplaneConfig struct {
	// The container where the vtysh and FRR daemons are running, if it's nil then FRR is considered to be running
	// in the host netns.
	// However, there would be one host netns is allowed at most.
	ContainerName *string `yaml:"container_name,omitempty" json:"container_name,omitempty"`

	DebugBGPUpdates  *bool `yaml:"debug_bgp_updates,omitempty" json:"debug_bgp_updates,omitempty"`
	DebugOSPFUpdates *bool `yaml:"debug_ospf_updates,omitempty" json:"debug_ospf_updates,omitempty"`
	DebugRPKI        *bool `yaml:"debug_rpki,omitempty" json:"debug_rpki,omitempty"`

	OSPFv2   []pkgprotocolospfv2.OSPFV2Config `yaml:"ospfv2,omitempty" json:"ospfv2,omitempty"`
	BGP      []pkgprotocolbgp.BGPConfig       `yaml:"bgp,omitempty" json:"bgp,omitempty"`
	RPKI     []pkgprotocolbgp.BGPRPKIConfig   `yaml:"rpki,omitempty" json:"rpki,omitempty"`
	RouteMap []pkgprotocolbgp.RouteMapConfig  `yaml:"route_map,omitempty" json:"route_map,omitempty"`
}

type NodeConfig struct {
	FRRContainers []pkgfrrcontainer.FRRContainerConfig `yaml:"frr_containers,omitempty" json:"frr_containers,omitempty"`

	// Currently, the implementation of the controlplane are largely outsourced to (maybe containerized) FRR instance.
	Controlplane []ControlplaneConfig `yaml:"controlplane,omitempty" json:"controlplane,omitempty"`
	Dataplane    *DataplaneConfig     `yaml:"dataplane,omitempty" json:"dataplane,omitempty"`

	// The list of containers to scan when doing a reconciliation loop
	Containers []string `yaml:"containers,omitempty" json:"containers,omitempty"`

	// By default, it would use $CWD/.go-reconciler-state as the stateful directory.
	// There is a GetStatefulDir method in pkgutils model for it.
	StatefulDir string `yaml:"stateful_dir,omitempty" json:"stateful_dir,omitempty"`
}

const DefaultStatefulDirRel = ".go-reconciler-state"

type DataplaneConfig struct {
	OpenVPN   pkgopenvpn2.OpenVPN2ConfigurationList            `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
	WireGuard pkginterfacewireguard.WireGuardConfigurationList `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`
	VXLAN     pkginterfacevxlan.VXLANConfigurationList         `yaml:"vxlan,omitempty" json:"vxlan,omitempty"`
	VethPair  pkginterfaceveth.VethPairConfigurationList       `yaml:"veth,omitempty" json:"veth,omitempty"`
	Bridge    pkginterfacebridge.BridgeConfigurationList       `yaml:"bridge,omitempty" json:"bridge,omitempty"`
	Dummy     pkginterfacedummy.DummyConfigurationList         `yaml:"dummy,omitempty" json:"dummy,omitempty"`
}
