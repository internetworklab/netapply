package dummy

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type DummyConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	VRF           *string                            `yaml:"vrf,omitempty" json:"vrf,omitempty"`

	// Soft deletion support
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty"`
}

type DummyInterfaceChangeSet struct {
	ContainerName     *string
	InterfaceName     string
	AddressesToRemove []*netlink.Addr
	AddressesToAdd    []*netlink.Addr
	VRFToSet          *string
}

type DummyConfigurationList struct {
	Containers []string      `yaml:"containers" json:"containers"`
	Dummies    []DummyConfig `yaml:"dummies" json:"dummies"`
}
