package wireguard

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	PrivateKey    string                             `yaml:"privatekey" json:"privatekey"`
	Peers         []WireGuardPeerConfig              `yaml:"peers,omitempty" json:"peers,omitempty"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	ListenPort    *int                               `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	MTU           *int                               `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

type WireGuardInterfaceChangeSet struct {
	ContainerName *string
	InterfaceName string

	PrivateKeyToSet *wgtypes.Key
	MTUToSet        *int
	ListenPortToSet *int

	PeersToRemove map[string]*wgtypes.Peer
	PeersToAdd    map[string]wgtypes.PeerConfig

	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
}

type WireGuardPeerConfig struct {
	PublicKey  string   `yaml:"publickey" json:"publickey"`
	Endpoint   *string  `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	AllowedIPs []string `yaml:"allowedips,omitempty" json:"allowedips,omitempty"`
}

type WireGuardConfigurationList []WireGuardConfig
