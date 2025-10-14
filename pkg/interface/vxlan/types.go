package vxlan

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type VXLANConfig struct {
	Name string `yaml:"name" json:"name"`

	// This is VNI, 24-bits integer, stored in low 24 bits in a uint32
	VXLANID uint32 `yaml:"vxlan_id" json:"vxlan_id"`

	LocalIP       *string                            `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	MTU           *int                               `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	Nolearning    *bool                              `yaml:"nolearning,omitempty" json:"nolearning,omitempty"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`

	// To explicitly specify the underlay interface, also to automatically calculate appropriate MTU.
	Dev      *string `yaml:"dev,omitempty" json:"dev,omitempty"`
	DestPort *uint16
}

type VXLANInterfaceChangeSet struct {
	AddressesToAdd    []*netlink.Addr
	AddressedToRemove []*netlink.Addr
	MTUToSet          *int
	ContainerName     *string
	InterfaceName     string
}

type VXLANConfigurationList []VXLANConfig
