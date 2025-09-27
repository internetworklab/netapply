package bridge

import (
	pkginterfacecommon "example.com/connector/pkg/interface/common"
	"github.com/vishvananda/netlink"
)

type BridgeConfig struct {
	Name            string                             `yaml:"name" json:"name"`
	SlaveInterfaces []string                           `yaml:"slave_interfaces,omitempty" json:"slave_interfaces,omitempty"`
	ContainerName   *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses       []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type BridgeInterfaceChangeSet struct {
	InterfaceToEnslave map[string]interface{}
	InterfaceToUnslave map[string]interface{}
	ContainerName      *string
	InterfaceName      string
	AddressesToAdd     []*netlink.Addr
	AddressesToRemove  []*netlink.Addr
}

type BridgeConfigurationList []BridgeConfig
