package dummy

import (
	pkginterfacecommon "example.com/connector/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type DummyConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type DummyInterfaceChangeSet struct {
	ContainerName     *string
	InterfaceName     string
	AddressesToRemove []*netlink.Addr
	AddressesToAdd    []*netlink.Addr
}

type DummyConfigurationList []DummyConfig
