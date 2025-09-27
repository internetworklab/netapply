package models

import (
	pkgdocker "example.com/connector/pkg/docker"
	pkginterfacebridge "example.com/connector/pkg/interface/bridge"
	pkginterfacedummy "example.com/connector/pkg/interface/dummy"
	pkginterfaceveth "example.com/connector/pkg/interface/veth"
	pkginterfacevxlan "example.com/connector/pkg/interface/vxlan"
	pkginterfacewireguard "example.com/connector/pkg/interface/wireguard"
	pkgopenvpn2 "example.com/connector/pkg/openvpn2"
	pkgprotocolbgp "example.com/connector/pkg/protocol/bgp"
	pkgprotocolospf "example.com/connector/pkg/protocol/ospf"
)

type GlobalConfig struct {
	Nodes map[string]NodeConfig `yaml:"nodes" json:"nodes"`
}

type ControlplaneConfig struct {
	OSPF              []pkgprotocolospf.OSPFConfig `yaml:"ospf,omitempty" json:"ospf,omitempty"`
	BGP               []pkgprotocolbgp.BGPConfig   `yaml:"bgp,omitempty" json:"bgp,omitempty"`
	ContainerName     *string                      `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	HostPatchDir      string                       `yaml:"host_patch_dir,omitempty" json:"host_patch_dir,omitempty"`
	ContainerPatchDir string                       `yaml:"container_patch_dir,omitempty" json:"container_patch_dir,omitempty"`
}

type NodeConfig struct {
	DockerContainers []pkgdocker.DockerContainerConfig `yaml:"docker_containers,omitempty" json:"docker_containers,omitempty"`
	Controlplane     *ControlplaneConfig               `yaml:"controlplane,omitempty" json:"controlplane,omitempty"`
	Dataplane        *DataplaneConfig                  `yaml:"dataplane,omitempty" json:"dataplane,omitempty"`
	Containers       []string                          `yaml:"containers,omitempty" json:"containers,omitempty"`
}

type DataplaneConfig struct {
	OpenVPN   pkgopenvpn2.OpenVPN2ConfigurationList            `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
	WireGuard pkginterfacewireguard.WireGuardConfigurationList `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`
	VXLAN     pkginterfacevxlan.VXLANConfigurationList         `yaml:"vxlan,omitempty" json:"vxlan,omitempty"`
	VethPair  pkginterfaceveth.VethPairConfigurationList       `yaml:"veth,omitempty" json:"veth,omitempty"`
	Bridge    pkginterfacebridge.BridgeConfigurationList       `yaml:"bridge,omitempty" json:"bridge,omitempty"`
	Dummy     pkginterfacedummy.DummyConfigurationList         `yaml:"dummy,omitempty" json:"dummy,omitempty"`
}
