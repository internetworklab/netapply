package dummy

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type DummyConfig struct {
	Name      string                             `yaml:"name" json:"name"`
	Container *pkginterfacecommon.ContainerInfo  `yaml:"container,omitempty" json:"container,omitempty" bson:"container,omitempty"`
	Addresses []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	VRF       *string                            `yaml:"vrf,omitempty" json:"vrf,omitempty"`

	// Soft deletion support
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty"`
}

type DummyInterfaceChangeSet struct {
	origin            *DummyConfig
	AddressesToRemove []*netlink.Addr
	AddressesToAdd    []*netlink.Addr
	VRFToSet          *string
}

type DummyConfigurationList struct {
	Containers []pkginterfacecommon.ContainerInfo `yaml:"containers" json:"containers"`
	Dummies    []DummyConfig                      `yaml:"dummies" json:"dummies"`
}
