package vxlan

import (
	pkginterfacecommon "example.com/connector/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type VXLANConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	VXLANID       int                                `yaml:"vxlan_id" json:"vxlan_id"`
	LocalIP       *string                            `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	MTU           *int                               `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	Nolearning    *bool                              `yaml:"nolearning,omitempty" json:"nolearning,omitempty"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type VXLANInterfaceChangeSet struct {
	AddressesToAdd    []*netlink.Addr
	AddressedToRemove []*netlink.Addr
	MTUToSet          *int
	ContainerName     *string
	InterfaceName     string
}

type VXLANConfigurationList []VXLANConfig
