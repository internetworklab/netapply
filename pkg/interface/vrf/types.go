package vrf

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type VRFConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	TableId       uint32                             `yaml:"table_id" json:"table_id"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type VRFConfigurationList []VRFConfig

const VRFNameEmpty = ""
const VRFNameDefault = "default"

// If the master index of a link is 0, we consider its VRF as default VRF
const DefaultVRFIndex int = 0

type VRFChangeSet struct {
	ContainerName     *string
	InterfaceName     string
	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
	NeedToSetUp       bool
}
