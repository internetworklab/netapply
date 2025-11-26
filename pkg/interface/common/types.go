package common

import (
	"github.com/vishvananda/netlink"
)

// +k8s:deepcopy-gen=true
type AddressConfig struct {
	Peer  *string `yaml:"peer,omitempty" json:"peer,omitempty" bson:"peer,omitempty"`
	Local *string `yaml:"local,omitempty" json:"local,omitempty" bson:"local,omitempty"`
	CIDR  *string `yaml:"cidr,omitempty" json:"cidr,omitempty" bson:"cidr,omitempty"`
}

type AddrsChangeSet struct {
	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
}

// +k8s:deepcopy-gen=true
type ContainerInfo struct {
	Docker    *string `yaml:"docker,omitempty" json:"docker,omitempty" bson:"docker,omitempty"`
	Podman    *string `yaml:"podman,omitempty" json:"podman,omitempty" bson:"podman,omitempty"`
	NetnsPath *string `yaml:"netns_path,omitempty" json:"netns_path,omitempty" bson:"netns_path,omitempty"`

	// When specified, would use host netns, however, mostly you should not use this, it's dangerous.
	HostNetns *bool   `yaml:"host_netns,omitempty" json:"host_netns,omitempty" bson:"host_netns,omitempty"`
}

// +k8s:deepcopy-gen=true
type CommonInterfaceStatus struct {
	Addresses []string `yaml:"addresses" json:"addresses" bson:"addresses"`
	MTU       int      `yaml:"mtu" json:"mtu" bson:"mtu"`
	OperState string   `yaml:"oper_state" json:"oper_state" bson:"oper_state"`
	Flags     string   `yaml:"flags" json:"flags" bson:"flags"`
}
