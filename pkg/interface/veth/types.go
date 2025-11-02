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
	VRF           *string                            `yaml:"vrf,omitempty" json:"vrf,omitempty"`

	// A stub veth simply represents the another end of a veth pair, it's not actually created or actually reconciled.
	Stub bool `yaml:"stub,omitempty" json:"stub,omitempty"`

	// Soft deletion support
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty"`
}

type VethPairPeerChangeSet struct {
	ContainerName  *string
	InterfaceName  string
	AddressesToAdd []*netlink.Addr
	AddressesToDel []*netlink.Addr
	MTUToSet       *int
	VRFToSet       *string
}

type VethPairChangeSet struct {
	Local *VethPairPeerChangeSet
	Peer  *VethPairPeerChangeSet
}

type VethPairConfigurationList struct {
	Containers []string         `yaml:"containers" json:"containers"`
	VethPairs  []VethPairConfig `yaml:"veth_pairs" json:"veth_pairs"`
}

type VethPairPlacementStatus struct {
	FoundInPrimaryNetns   bool
	FoundInSecondaryNetns bool
}
