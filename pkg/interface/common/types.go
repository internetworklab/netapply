package common

import (
	"github.com/vishvananda/netlink"
)

type AddressConfig struct {
	Peer  *string `yaml:"peer,omitempty" json:"peer,omitempty" bson:"peer,omitempty"`
	Local *string `yaml:"local,omitempty" json:"local,omitempty" bson:"local,omitempty"`
	CIDR  *string `yaml:"cidr,omitempty" json:"cidr,omitempty" bson:"cidr,omitempty"`
}

type AddrsChangeSet struct {
	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
}

type ContainerInfo struct {
	Docker    *string `yaml:"docker,omitempty" json:"docker,omitempty" bson:"docker,omitempty"`
	Podman    *string `yaml:"podman,omitempty" json:"podman,omitempty" bson:"podman,omitempty"`
	NetnsPath *string `yaml:"netns_path,omitempty" json:"netns_path,omitempty" bson:"netns_path,omitempty"`
}

type CommonInterfaceStatus struct {
	Addresses []string `yaml:"addresses" json:"addresses" bson:"addresses"`
	MTU       int      `yaml:"mtu" json:"mtu" bson:"mtu"`
}
