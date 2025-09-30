package openvpn2

import (
	pkgdocker "example.com/connector/pkg/docker"
)

type OpenVPN2Role string

const (
	OpenVPN2RoleClient OpenVPN2Role = "client"
	OpenVPN2RoleServer OpenVPN2Role = "server"
)

type OpenVPN2Proto string

const (
	OpenVPN2ProtoTCP       OpenVPN2Proto = "tcp"
	OpenVPN2ProtoUDP       OpenVPN2Proto = "udp"
	OpenVPN2ProtoTCPServer OpenVPN2Proto = "tcp-server"
	OpenVPN2ProtoUDPServer OpenVPN2Proto = "udp-server"
	OpenVPN2ProtoTCPClient OpenVPN2Proto = "tcp-client"
	OpenVPN2ProtoUDPClient OpenVPN2Proto = "udp-client"
)

type OpenVPN2Topology string

const (
	OpenVPN2TopologySubnet OpenVPN2Topology = "subnet"
	OpenVPN2TopologyNet30  OpenVPN2Topology = "net30"
)

type OpenVPN2KeepaliveConfig struct {
	IntervalSecs int `json:"interval_secs" yaml:"interval_secs"`
	PatienceSecs int `json:"patience_secs" yaml:"patience_secs"`
}

type OpenVPN2RemoteConfig struct {
	Host string `json:"host" yaml:"host"`
	Port int    `json:"port" yaml:"port"`
}

type OpenVPN2RemoteTLSCertType string

const (
	OpenVPN2RemoteTLSCertTypeServer OpenVPN2RemoteTLSCertType = "server"
	OpenVPN2RemoteTLSCertTypeClient OpenVPN2RemoteTLSCertType = "client"
)

type OpenVPN2Instance struct {
	Name       string                `openvpn2:"-" yaml:"name"`
	Client     *bool                 `openvpn2:"client" yaml:"client,omitempty"`
	Server     *bool                 `openvpn2:"server" yaml:"server,omitempty"`
	Port       *int                  `openvpn2:"port" yaml:"port,omitempty"`
	Dev        string                `openvpn2:"dev" yaml:"dev"`
	Proto      OpenVPN2Proto         `openvpn2:"proto" yaml:"proto"`
	Remote     *OpenVPN2RemoteConfig `openvpn2:"remote" yaml:"remote,omitempty"`
	NoBind     *bool                 `openvpn2:"no-bind" yaml:"no_bind,omitempty"`
	PersistTun *bool                 `openvpn2:"persist-tun" yaml:"persist_tun,omitempty"`
	HttpProxy  *OpenVPN2RemoteConfig `openvpn2:"http-proxy" yaml:"http_proxy,omitempty"`

	// Path to the TLS cert file for authenticate to the peer, PEM x509v2 format
	// This only affect how to generate the openvpn cli arguments,
	// to specify the path of cert file to provided,
	// use the HostTLSCertFile field.
	CertFile string `openvpn2:"cert" yaml:"cert_file"`

	// Path to the TLS cert key file, PEM format
	// This only affect how to generate the openvpn cli arguments,
	// to specify the path of cert key file to provided,
	// use the HostTLSKeyFile field.
	KeyFile string `openvpn2:"key" yaml:"key_file"`

	// Path to the DH PEM file is only needed when in server mode.
	// This only affect how to generate the openvpn cli arguments,
	// to specify the path of dh pem file to provided,
	// use the HostDHPEMFile field.
	DHPEMFile *string `openvpn2:"dh" yaml:"dh_pem_file,omitempty"`

	PeerFingerprint     string                     `openvpn2:"peer-fingerprint" yaml:"peer_fingerprint"`
	RemoteCertTls       *OpenVPN2RemoteTLSCertType `openvpn2:"remote-cert-tls" yaml:"remote_cert_tls,omitempty"`
	Verb                *int                       `openvpn2:"verb" yaml:"verb,omitempty"`
	TLSServer           *bool                      `openvpn2:"tls-server" yaml:"tls_server,omitempty"`
	DataCiphers         *string                    `openvpn2:"data-ciphers" yaml:"data_ciphers,omitempty"`
	Topology            *OpenVPN2Topology          `openvpn2:"topology" yaml:"topology,omitempty"`
	ServerBridge        *bool                      `openvpn2:"server-bridge" yaml:"server_bridge,omitempty"`
	ClientToClient      *bool                      `openvpn2:"client-to-client" yaml:"client_to_client,omitempty"`
	KeepaliveIntvSecs   *OpenVPN2KeepaliveConfig   `openvpn2:"keepalive" yaml:"keepalive,omitempty"`
	StatusFile          *string                    `openvpn2:"status" yaml:"status_file,omitempty"`
	ExplicitExitNotify  *bool                      `openvpn2:"explicit-exit-notify" yaml:"explicit_exit_notify,omitempty"`
	UpCMD               *string                    `openvpn2:"up" yaml:"up_cmd,omitempty"`
	ScriptSecurityLevel *int                       `openvpn2:"script-security" yaml:"script_security_level,omitempty"`
	ResolvRetry         *string                    `openvpn2:"resolv-retry" yaml:"resolv_retry,omitempty"`
	LLAddr              *string                    `openvpn2:"lladdr" yaml:"lladdr,omitempty"`

	// The openvpn2 executable path in the container, by default it's "openvpn"
	ExecutablePath *string `openvpn2:"-" yaml:"executable_path,omitempty" json:"executable_path,omitempty"`

	// Since there's no official openvpn2 image, so the user have to specify it explicitly.
	Image string `openvpn2:"-" yaml:"image" json:"image"`

	// Hostname of the container
	HostName *string `openvpn2:"-" yaml:"hostname,omitempty" json:"hostname,omitempty"`

	// Name of the container, since openvpn2 will be running inside a container
	ContainerName string `openvpn2:"-" yaml:"container_name" json:"container_name"`

	// Port mappings, in case to publish container ports to host's public network
	// Usually tcp port 1194 should be published.
	Ports map[string][]pkgdocker.DockerPortMapping `yaml:"ports,omitempty" json:"ports,omitempty"`

	// Networks to join, the network must exist, if not, one should manually create
	// the docker network using command such as `docker network create <network_name>` to create it before use.
	DockerNetworks []string `openvpn2:"-" yaml:"docker_networks,omitempty" json:"docker_networks,omitempty"`

	// Path to the TLS cert file in the host
	// By default, it would be bind mount to /etc/openvpn/certs/cert.pem in the container
	HostTLSCertFile *string `openvpn2:"-" yaml:"host_tls_cert_file,omitempty" json:"host_tls_cert_file,omitempty"`

	// Path to the TLS cert key file in the host
	// By default, it would be bind mount to /etc/openvpn/certs/key.pem in the container
	HostTLSKeyFile *string `openvpn2:"-" yaml:"host_tls_key_file,omitempty" json:"host_tls_key_file,omitempty"`

	// Path to the DH PEM file in the host, only needed when in server mode
	// By default, it would be bind mount to /etc/openvpn/certs/dh.pem in the container (when provided)
	HostDHPEMFile *string `openvpn2:"-" yaml:"host_dh_pem_file,omitempty" json:"host_dh_pem_file,omitempty"`
}

type OpenVPN2ConfigurationList []OpenVPN2Instance

type OpenVPN2InterfaceCanceller struct {
	ContainerName string
}
