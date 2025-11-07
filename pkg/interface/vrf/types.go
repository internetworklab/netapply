package vrf

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type VRFConfig struct {
	Name      string                             `yaml:"name" json:"name"`
	TableId   uint32                             `yaml:"table_id" json:"table_id"`
	Addresses []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`

	// Soft deletion support
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty"`

	// Optional fields for containerized resources
	ContainerInfo *pkginterfacecommon.ContainerInfo `yaml:"container,omitempty" json:"container,omitempty"`
}

type VRFConfigurationList struct {
	Containers []pkginterfacecommon.ContainerInfo `yaml:"containers" json:"containers"`
	VRFs       []VRFConfig                        `yaml:"vrfs" json:"vrfs"`
}

type VRFChangeSet struct {
	origin            *VRFConfig
	ContainerName     *string
	InterfaceName     string
	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
	NeedToSetUp       bool
}
