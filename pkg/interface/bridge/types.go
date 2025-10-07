package bridge

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
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

type BridgingConnectionConfig struct {
	Name          string  `yaml:"name" json:"name"`
	ContainerName *string `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	VethName      string  `yaml:"veth_name" json:"veth_name"`
	BridgeName    string  `yaml:"bridge_name" json:"bridge_name"`
}
