package wireguard

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardConfig struct {
	Name       string `yaml:"name" json:"name" bson:"name"`
	PrivateKey string `yaml:"privatekey,omitempty" json:"privatekey,omitempty" bson:"privatekey,omitempty"`

	// If privatekey is not set, privatekey_from will be checked, if privatekey_from is not nil and not empty,
	// it will be treated as an URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	PrivateKeyFrom *string                            `yaml:"privatekey_from,omitempty" json:"privatekey_from,omitempty" bson:"privatekey_from,omitempty"`
	Peers          []WireGuardPeerConfig              `yaml:"peers,omitempty" json:"peers,omitempty" bson:"peers,omitempty"`
	Addresses      []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty" bson:"addresses,omitempty"`
	Container      *pkginterfacecommon.ContainerInfo  `yaml:"container,omitempty" json:"container,omitempty" bson:"container,omitempty"`

	// If not specified, would be generated randomly from [11024, 65535]
	ListenPort *int `yaml:"listen_port,omitempty" json:"listen_port,omitempty" bson:"listen_port,omitempty"`

	MTU *int `yaml:"mtu,omitempty" json:"mtu,omitempty" bson:"mtu,omitempty"`

	VRF *string `yaml:"vrf,omitempty" json:"vrf,omitempty" bson:"vrf,omitempty"`

	// Use to store metadata or anything that is business-relevant.
	Additionals map[string]string `yaml:"additionals,omitempty" json:"additionals,omitempty" bson:"additionals,omitempty"`

	// When storing in database, use Node to distinguish which node the resource belongs to.
	// And ResourceId serves as the unique ID to distinguish the resource in the global scope.
	Node       *string `yaml:"node,omitempty" json:"node,omitempty" bson:"node,omitempty"`
	ResourceId *string `yaml:"resource_id,omitempty" json:"resource_id,omitempty" bson:"resource_id,omitempty"`

	// For soft-deletion
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty" bson:"deleted,omitempty"`
}

// +k8s:deepcopy-gen=true
type WireGuardPeerStatus struct {
	PublicKey           string   `yaml:"public_key" json:"public_key" bson:"public_key"`
	Endpoint            *string  `yaml:"endpoint,omitempty" json:"endpoint,omitempty" bson:"endpoint,omitempty"`
	AllowedIPs          []string `yaml:"allowedips,omitempty" json:"allowedips,omitempty" bson:"allowedips,omitempty"`

	// Seconds of PKL
	PersistentKeepalive *int     `yaml:"persistent_keepalive,omitempty" json:"persistent_keepalive,omitempty" bson:"persistent_keepalive,omitempty"`
	PresharedKey        *string  `yaml:"preshared_key,omitempty" json:"preshared_key,omitempty" bson:"preshared_key,omitempty"`
}

// +k8s:deepcopy-gen=true
type WireGuardInterfaceStatus struct {
	InterfaceStatus *pkginterfacecommon.CommonInterfaceStatus `yaml:"interface_status" json:"interface_status" bson:"interface_status"`
	PublicKey       string                                    `yaml:"public_key" json:"public_key" bson:"public_key"`
	ListenPort      int                                       `yaml:"listen_port" json:"listen_port" bson:"listen_port"`
	Peers           []WireGuardPeerStatus                     `yaml:"peers" json:"peers" bson:"peers"`
}

type WireGuardInterfaceChangeSet struct {
	origin *WireGuardConfig

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
	PublicKey           string `yaml:"publickey,omitempty" json:"publickey,omitempty" bson:"publickey,omitempty"`
	PersistentKeepalive *int   `yaml:"persistent_keepalive,omitempty" json:"persistent_keepalive,omitempty" bson:"persistent_keepalive,omitempty"`

	PresharedKey string `yaml:"presharedkey,omitempty" json:"presharedkey,omitempty" bson:"presharedkey,omitempty"`

	// If PresharedKey is not set, PresharedKeyFrom will be checked, if PresharedKeyFrom is not nil and not empty,
	// it will be treated as an URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	PresharedKeyFrom *string `yaml:"presharedkey_from,omitempty" json:"presharedkey_from,omitempty" bson:"presharedkey_from,omitempty"`

	// If PublicKey is not set, PublicKeyFrom will be checked, if PublicKeyFrom is not nil and not empty,
	// it will be treated as an URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	PublicKeyFrom *string `yaml:"publickey_from,omitempty" json:"publickey_from,omitempty" bson:"publickey_from,omitempty"`

	Endpoint   *string  `yaml:"endpoint,omitempty" json:"endpoint,omitempty" bson:"endpoint,omitempty"`
	AllowedIPs []string `yaml:"allowedips,omitempty" json:"allowedips,omitempty" bson:"allowedips,omitempty"`
}

type WireGuardConfigurationList struct {
	Containers       []pkginterfacecommon.ContainerInfo `yaml:"containers" json:"containers"`
	WireGuardConfigs []WireGuardConfig                  `yaml:"wireguard_configs" json:"wireguard_configs"`
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
