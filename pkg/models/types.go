package models

import (
	pkgfrrdaemons "example.com/connector/pkg/frr/daemons"
	pkginterfacebridge "example.com/connector/pkg/interface/bridge"
	pkginterfacedummy "example.com/connector/pkg/interface/dummy"
	pkginterfaceveth "example.com/connector/pkg/interface/veth"
	pkginterfacevxlan "example.com/connector/pkg/interface/vxlan"
	pkginterfacewireguard "example.com/connector/pkg/interface/wireguard"
	pkgopenvpn2 "example.com/connector/pkg/openvpn2"
	pkgprotocolbgp "example.com/connector/pkg/protocol/bgp"
	pkgprotocolospfv2 "example.com/connector/pkg/protocol/ospfv2"
)

type GlobalConfig struct {
	Nodes map[string]NodeConfig `yaml:"nodes" json:"nodes"`
}

type ControlplaneConfig struct {
	OSPFv2 []pkgprotocolospfv2.OSPFV2Config `yaml:"ospfv2,omitempty" json:"ospfv2,omitempty"`
	BGP    []pkgprotocolbgp.BGPConfig       `yaml:"bgp,omitempty" json:"bgp,omitempty"`

	// The container where the vtysh and FRR daemons are running, if it's nil then FRR is considered to be running
	// in the host netns.
	ContainerName *string `yaml:"container_name,omitempty" json:"container_name,omitempty"`
}

type FRRContainerConfig struct {
	ContainerName string                         `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Daemons       pkgfrrdaemons.FRRDaemonsConfig `yaml:"daemons,omitempty" json:"daemons,omitempty"`
}

type NodeConfig struct {
	FRRContainers []FRRContainerConfig `yaml:"frr_containers,omitempty" json:"frr_containers,omitempty"`
	Controlplane  *ControlplaneConfig  `yaml:"controlplane,omitempty" json:"controlplane,omitempty"`
	Dataplane     *DataplaneConfig     `yaml:"dataplane,omitempty" json:"dataplane,omitempty"`

	// The list of containers to scan when doing a reconciliation loop
	Containers []string `yaml:"containers,omitempty" json:"containers,omitempty"`

	// By default, it would use $CWD/.go-reconciler-state as the stateful directory.
	StatefulDir string `yaml:"stateful_dir,omitempty" json:"stateful_dir,omitempty"`
}

type DataplaneConfig struct {
	OpenVPN   pkgopenvpn2.OpenVPN2ConfigurationList            `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
	WireGuard pkginterfacewireguard.WireGuardConfigurationList `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`
	VXLAN     pkginterfacevxlan.VXLANConfigurationList         `yaml:"vxlan,omitempty" json:"vxlan,omitempty"`
	VethPair  pkginterfaceveth.VethPairConfigurationList       `yaml:"veth,omitempty" json:"veth,omitempty"`
	Bridge    pkginterfacebridge.BridgeConfigurationList       `yaml:"bridge,omitempty" json:"bridge,omitempty"`
	Dummy     pkginterfacedummy.DummyConfigurationList         `yaml:"dummy,omitempty" json:"dummy,omitempty"`
}
