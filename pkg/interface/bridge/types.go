package bridge

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	"github.com/vishvananda/netlink"
)

type BridgeConfig struct {
	Name            string                             `yaml:"name" json:"name"`
	SlaveInterfaces []string                           `yaml:"slave_interfaces,omitempty" json:"slave_interfaces,omitempty"`
	Addresses       []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	VRF             *string                            `yaml:"vrf,omitempty" json:"vrf,omitempty"`

	// Soft deletion support
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty"`

	// Optional fields for containerized resources
	Container      *pkginterfacecommon.ContainerInfo  `yaml:"container,omitempty" json:"container,omitempty" bson:"container,omitempty"`
}

type BridgeInterfaceChangeSet struct {
	NetnsInfo          *pkgnetns.NetNsInfo
	InterfaceToEnslave map[string]interface{}
	InterfaceToUnslave map[string]interface{}
	ContainerName      *string
	InterfaceName      string
	AddressesToAdd     []*netlink.Addr
	AddressesToRemove  []*netlink.Addr
	VRFToSet           *string
}

type BridgeConfigurationList struct {
	Containers []pkginterfacecommon.ContainerInfo `yaml:"containers" json:"containers"`
	Bridges    []BridgeConfig                     `yaml:"bridges" json:"bridges"`
}

type BridgingConnectionConfig struct {
	Name          string  `yaml:"name" json:"name"`
	ContainerName *string `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	VethName      string  `yaml:"veth_name" json:"veth_name"`
	BridgeName    string  `yaml:"bridge_name" json:"bridge_name"`
}
