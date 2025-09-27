package common

import "github.com/vishvananda/netlink"

type AddressConfig struct {
	Peer  *string `yaml:"peer,omitempty" json:"peer,omitempty"`
	Local *string `yaml:"local,omitempty" json:"local,omitempty"`
	CIDR  *string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
}

type AddrsChangeSet struct {
	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
}
