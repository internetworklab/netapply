package openvpn2

import (
	"fmt"

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

func (ovp *OpenVPN2RemoteTLSCertType) ToCLIArgs() []string {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%v", *ovp))
	}
	return res
}

type OpenVPN2Instance struct {
	Name                string                           `openvpn2:"-" yaml:"name"`
	Client              *bool                            `openvpn2:"client" yaml:"client,omitempty"`
	Server              *bool                            `openvpn2:"server" yaml:"server,omitempty"`
	Port                *int                             `openvpn2:"port" yaml:"port,omitempty"`
	Dev                 string                           `openvpn2:"dev" yaml:"dev"`
	Proto               OpenVPN2Proto                    `openvpn2:"proto" yaml:"proto"`
	Remote              *OpenVPN2RemoteConfig            `openvpn2:"remote" yaml:"remote,omitempty"`
	NoBind              *bool                            `openvpn2:"no-bind" yaml:"no_bind,omitempty"`
	PersistTun          *bool                            `openvpn2:"persist-tun" yaml:"persist_tun,omitempty"`
	HttpProxy           *OpenVPN2RemoteConfig            `openvpn2:"http-proxy" yaml:"http_proxy,omitempty"`
	CertFile            string                           `openvpn2:"cert" yaml:"cert_file"`
	KeyFile             string                           `openvpn2:"key" yaml:"key_file"`
	DHPEMFile           *string                          `openvpn2:"dh" yaml:"dh,omitempty"`
	PeerFingerprint     string                           `openvpn2:"peer-fingerprint" yaml:"peer_fingerprint"`
	RemoteCertTls       *OpenVPN2RemoteTLSCertType       `openvpn2:"remote-cert-tls" yaml:"remote_cert_tls,omitempty"`
	Verb                *int                             `openvpn2:"verb" yaml:"verb,omitempty"`
	TLSServer           *bool                            `openvpn2:"tls-server" yaml:"tls_server,omitempty"`
	DataCiphers         *string                          `openvpn2:"data-ciphers" yaml:"data_ciphers,omitempty"`
	Topology            *OpenVPN2Topology                `openvpn2:"topology" yaml:"topology,omitempty"`
	ServerBridge        *bool                            `openvpn2:"server-bridge" yaml:"server_bridge,omitempty"`
	ClientToClient      *bool                            `openvpn2:"client-to-client" yaml:"client_to_client,omitempty"`
	KeepaliveIntvSecs   *OpenVPN2KeepaliveConfig         `openvpn2:"keepalive" yaml:"keepalive,omitempty"`
	StatusFile          *string                          `openvpn2:"status" yaml:"status_file,omitempty"`
	ExplicitExitNotify  *bool                            `openvpn2:"explicit-exit-notify" yaml:"explicit_exit_notify,omitempty"`
	UpCMD               *string                          `openvpn2:"up" yaml:"up_cmd,omitempty"`
	ScriptSecurityLevel *int                             `openvpn2:"script-security" yaml:"script_security_level,omitempty"`
	ResolvRetry         *string                          `openvpn2:"resolv-retry" yaml:"resolv_retry,omitempty"`
	LLAddr              *string                          `openvpn2:"lladdr" yaml:"lladdr,omitempty"`
	DockerContainer     *pkgdocker.DockerContainerConfig `openvpn2:"-" yaml:"docker_container,omitempty"`
	ExecutablePath      *string                          `openvpn2:"-" yaml:"executable_path,omitempty" json:"executable_path,omitempty"`
}

type OpenVPN2ConfigurationList []OpenVPN2Instance

type OpenVPN2InterfaceCanceller struct {
	ContainerName string
}
