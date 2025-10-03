package veth

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type VethPairConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Peer          *VethPairConfig                    `yaml:"peer,omitempty" json:"peer,omitempty"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	MTU           *int                               `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

type VethPairPeerChangeSet struct {
	ContainerName  *string
	InterfaceName  string
	AddressesToAdd []*netlink.Addr
	AddressesToDel []*netlink.Addr
	MTUToSet       *int
}

type VethPairChangeSet struct {
	Local *VethPairPeerChangeSet
	Peer  *VethPairPeerChangeSet
}

type VethPairConfigurationList []VethPairConfig

type VethPairPlacementStatus struct {
	FoundInPrimaryNetns   bool
	FoundInSecondaryNetns bool
}
