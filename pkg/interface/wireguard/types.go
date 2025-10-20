package wireguard

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardConfig struct {
	Name       string `yaml:"name" json:"name"`
	PrivateKey string `yaml:"privatekey,omitempty" json:"privatekey,omitempty"`

	// If privatekey is not set, privatekey_from will be checked, if privatekey_from is not nil and not empty,
	// it will be treated as an URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	PrivateKeyFrom *string                            `yaml:"privatekey_from,omitempty" json:"privatekey_from,omitempty"`
	Peers          []WireGuardPeerConfig              `yaml:"peers,omitempty" json:"peers,omitempty"`
	Addresses      []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	ContainerName  *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	ListenPort     *int                               `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	MTU            *int                               `yaml:"mtu,omitempty" json:"mtu,omitempty"`

	VRF *string `yaml:"vrf,omitempty" json:"vrf,omitempty"`

	// Use to store metadata or anything that is business-relevant.
	Additionals map[string]string `yaml:"additionals,omitempty" json:"additionals,omitempty"`
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

	VRFToSet *string
}

type WireGuardPeerConfig struct {
	PublicKey           string `yaml:"publickey,omitempty" json:"publickey,omitempty"`
	PersistentKeepalive *int   `yaml:"persistent_keepalive,omitempty" json:"persistent_keepalive,omitempty"`

	PresharedKey string `yaml:"presharedkey,omitempty" json:"presharedkey,omitempty"`

	// If PresharedKey is not set, PresharedKeyFrom will be checked, if PresharedKeyFrom is not nil and not empty,
	// it will be treated as an URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	PresharedKeyFrom *string `yaml:"presharedkey_from,omitempty" json:"presharedkey_from,omitempty"`

	// If PublicKey is not set, PublicKeyFrom will be checked, if PublicKeyFrom is not nil and not empty,
	// it will be treated as an URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	PublicKeyFrom *string `yaml:"publickey_from,omitempty" json:"publickey_from,omitempty"`

	Endpoint   *string  `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	AllowedIPs []string `yaml:"allowedips,omitempty" json:"allowedips,omitempty"`

	// When deploy in intranet, the endpoint might not successfully converge to the endpoint specified in the spec,
	// Enabling this flag might result in the reconciliation failed to converge.
	ForceRecheckEndpoint *bool `yaml:"force_recheck_endpoint,omitempty" json:"force_recheck_endpoint,omitempty"`
}

type WireGuardConfigurationList struct {
	Containers       []string          `yaml:"containers" json:"containers"`
	WireGuardConfigs []WireGuardConfig `yaml:"wireguard_configs" json:"wireguard_configs"`
}

// Might be used to convert any plaintext or binary representation of WireGuard config to WireGuardConfig object in memory.
type WireGuardConfigAdapter interface {
	ToWireGuardConfig(raw []byte) (*WireGuardConfig, error)
}

type ExtendedINIWireGuardConfigAdapter struct{}

const WGINIKeyListenPort string = "ListenPort"
const WGINIKeyPrivateKey string = "PrivateKey"
const WGINIKeyAllowedIPs string = "AllowedIPs"
const WGINIKeyEndpoint string = "Endpoint"
const WGINIKeyPublicKey string = "PublicKey"
const WGINIKeyPresharedKey string = "PresharedKey"
const WGINIKeyPersistentKeepalive string = "PersistentKeepalive"

const WGAdditionalKeyLinkLocal = "linklocal"
const WGAdditionalKeyPeerLinkLocal = "peerlinklocal"
const WGAdditionalKeyVRF = "vrf"
const WGAdditionalKeyConnectionID = "connid"
