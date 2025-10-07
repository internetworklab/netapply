package openvpn2

import (
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
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
	OpenVPN2TopologyP2P    OpenVPN2Topology = "p2p"
	OpenVPN2TopologyNet30  OpenVPN2Topology = "net30"
)

type OpenVPN2KeepaliveConfig struct {
	IntervalSecs int `json:"interval_secs" yaml:"interval_secs"`
	PatienceSecs int `json:"patience_secs" yaml:"patience_secs"`
}

type OpenVPN2RemoteConfig struct {
	Host  string  `json:"host" yaml:"host"`
	Port  int     `json:"port" yaml:"port"`
	Proto *string `json:"proto" yaml:"proto"`
}

type OpenVPN2RemoteTLSCertType string

const (
	OpenVPN2RemoteTLSCertTypeServer OpenVPN2RemoteTLSCertType = "server"
	OpenVPN2RemoteTLSCertTypeClient OpenVPN2RemoteTLSCertType = "client"
)

type OpenVPN2MajorMode string

const (
	OpenVPN2MajorModeP2P    OpenVPN2MajorMode = "p2p"
	OpenVPN2MajorModeServer OpenVPN2MajorMode = "server"
)

type OpenVPN2Instance struct {
	// Name of the container, since openvpn2 will be running inside a container
	Name string `openvpn2:"-" yaml:"name"`

	// A helper directive designed to simplify the configuration of OpenVPN's client mode. This directive is equivalent to:
	// ```
	// pull
	// tls-client
	// ```
	Client bool `openvpn2:"client" yaml:"client"`

	// A helper directive designed to simplify the configuration of OpenVPN's server mode. This directive will set up an OpenVPN server which will allocate addresses to clients out of the given network/netmask.
	Server bool `openvpn2:"server" yaml:"server"`

	// TCP/UDP port number or port name for both local and remote (sets both --lport and --rport options to given port).
	// The current default of 1194 represents the official IANA port number assignment for OpenVPN and has been used since version 2.0-beta17.
	// Previous versions used port 5000 as the default.
	Port *int `openvpn2:"port" yaml:"port,omitempty"`

	// Set OpenVPN major mode. By default, OpenVPN runs in point-to-point mode (p2p). OpenVPN 2.0 introduces a new mode (server) which implements a multi-client server capability.
	Mode *OpenVPN2MajorMode `openvpn2:"mode" yaml:"mode,omitempty"`

	// TUN/TAP virtual network device which can be tunX, tapX, null or an arbitrary name string (X can be omitted for a dynamic device.)
	// Valid syntaxes:
	// - `dev tun`
	// - `dev tap`
	// - `dev tapX` where X is a number
	// - `dev tunX` where X is a number
	Dev string `openvpn2:"dev" yaml:"dev"`

	// Use protocol p for communicating with remote host.
	// p can be udp, tcp-client, or tcp-server.
	// You can also limit OpenVPN to use only IPv4 or only IPv6 by
	// specifying p as udp4, tcp4-client, tcp4-server or udp6, tcp6-client, tcp6-server, respectively.
	Proto OpenVPN2Proto `openvpn2:"proto" yaml:"proto"`

	// Remote host name or IP address, port and protocol.
	// Valid syntaxes:
	// - `remote host`
	// - `remote host port`
	// - `remote host port proto`
	Remote *OpenVPN2RemoteConfig `openvpn2:"remote" yaml:"remote,omitempty"`

	// Do not bind to local address and port. The IP stack will allocate a dynamic port for returning packets. Since the value of the dynamic port could not be known in advance by a peer, this option is only suitable
	// for peers which will be initiating connections by using the --remote option.
	NoBind bool `openvpn2:"nobind" yaml:"no_bind"`

	// Don't close and reopen TUN/TAP device or run up/down scripts across SIGUSR1 or --ping-restart restarts.
	PersistTun bool `openvpn2:"persist-tun" yaml:"persist_tun"`

	// 	Connect to remote host through an HTTP proxy.
	HttpProxy *OpenVPN2RemoteConfig `openvpn2:"http-proxy" yaml:"http_proxy,omitempty"`

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

	// Specify a SHA256 fingerprint or list of SHA256 fingerprints to verify the peer certificate against.
	// The peer certificate must match one of the fingerprint or certificate verification will fail.
	// The option can also be inlined
	PeerFingerprint string `openvpn2:"peer-fingerprint" yaml:"peer_fingerprint"`

	// Require that peer certificate was signed with an explicit key usage and extended key usage based on RFC3280 TLS rules.
	// Valid syntaxes:
	// - `remote-cert-tls server`
	// - `remote-cert-tls client`
	RemoteCertTls *OpenVPN2RemoteTLSCertType `openvpn2:"remote-cert-tls" yaml:"remote_cert_tls,omitempty"`

	// Set output verbosity to n (default 1). Each level shows all info from the previous levels.
	// Level 3 is recommended if you want a good summary of what's happening without being swamped by output.
	// 0: No output except fatal errors
	// 1-4: Normal usage range
	// 5: Outputs R and W characters to the console for each packet read and write, uppercase is used for TCP/UDP packets and lowercase is used for TUN/TAP packets.
	// 6-11: Debug info range (see errlevel.h in the source code for additional information on debug levels).
	Verb *int `openvpn2:"verb" yaml:"verb,omitempty"`

	// Enable TLS and client role during TLS handshake.
	TLSClient *bool `openvpn2:"tls-client" yaml:"tls_client,omitempty"`

	// Enable TLS and assume server role during TLS handshake. Note that OpenVPN is designed as a peer-to-peer application. The designation of client or server is
	// only for the purpose of negotiating the TLS control channel.
	TLSServer *bool `openvpn2:"tls-server" yaml:"tls_server,omitempty"`

	// Restrict the allowed ciphers to be negotiated to the ciphers in cipher-list. cipher-list is a colon-separated list of ciphers, and defaults to AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305 when Chacha20-Poly1305 is available and otherwise AES-256-GCM:AES-128-GCM.
	DataCiphers *string `openvpn2:"data-ciphers" yaml:"data_ciphers,omitempty"`

	// Configure virtual addressing topology when running in --dev tun mode.
	// This directive has no meaning in --dev tap mode, which always uses a subnet topology.
	//
	// net30: Use a point-to-point topology, by allocating one /30 subnet per client. This is designed to allow point-to-point semantics when some or all of the connecting clients might be Windows systems. This is the default.
	// p2p: Use a point-to-point topology where the remote endpoint of the client's tun interface always points to the local endpoint of the server's tun interface. This mode allocates a single IP address per connecting client. Only use when none of the connecting clients are Windows systems.
	// subnet: Use a subnet rather than a point-to-point topology by configuring the tun interface with a local IP address and subnet mask, similar to the topology used in --dev tap and ethernet bridging mode. This mode allocates a single IP address per connecting client and works on Windows as well.
	//
	// TLDR: net30 has the best compatibility while p2p has little wastes.
	Topology *OpenVPN2Topology `openvpn2:"topology" yaml:"topology,omitempty"`

	// 	A helper directive similar to --server which is designed to simplify the configuration of
	// OpenVPN's server mode in ethernet bridging configurations.
	//
	// Valid syntaxes:
	// - `server-bridge gateway netmask pool-start-IP pool-end-IP`
	// - `server-bridge [nogw]`
	//
	// If --server-bridge is used without any parameters, it will enable a DHCP-proxy mode, where connecting OpenVPN clients will receive an
	// IP address for their TAP adapter from the DHCP server running on the OpenVPN server-side LAN. Note that only clients that support the binding
	// of a DHCP client with the TAP adapter (such as Windows) can support this mode. The optional nogw flag (advanced) indicates that gateway information should not be pushed to the client.
	// To configure ethernet bridging, you must first use your OS's bridging capability to bridge the TAP interface with the ethernet NIC interface.
	ServerBridge *bool `openvpn2:"server-bridge" yaml:"server_bridge,omitempty"`

	// 	Because the OpenVPN server mode handles multiple clients through a single tun or tap interface,
	// it is effectively a router. The --client-to-client flag tells OpenVPN to internally route client-to-client
	// traffic rather than pushing all client-originating traffic to the TUN/TAP interface.
	//
	// When this option is used, each client will "see" the other clients which are currently connected.
	// Otherwise, each client will only see the server. Don't use this option if you want to firewall tunnel traffic using custom, per-client rules.
	ClientToClient *bool `openvpn2:"client-to-client" yaml:"client_to_client,omitempty"`

	// A helper directive designed to simplify the expression of --ping and --ping-restart.
	// Valid syntax:
	// - `keepalive interval timeout`
	KeepaliveIntvSecs *OpenVPN2KeepaliveConfig `openvpn2:"keepalive" yaml:"keepalive,omitempty"`

	// Write operational status to file every n seconds. n defaults to 60 if not specified.
	// Valid syntaxes:
	// - `status file`
	// - `status file n`
	StatusFile []string `openvpn2:"status" yaml:"status_file,omitempty"`

	// In UDP client mode or point-to-point mode, send server/peer an exit notification if tunnel is restarted or OpenVPN process is exited.
	//  In client mode, on exit/restart, this option will tell the server to immediately close its client instance object rather than waiting for a timeout.
	ExplicitExitNotify *bool `openvpn2:"explicit-exit-notify" yaml:"explicit_exit_notify,omitempty"`

	// Executed after TCP/UDP socket bind and TUN/TAP open.
	UpCMD *string `openvpn2:"up" yaml:"up_cmd,omitempty"`

	// This directive offers policy-level control over OpenVPN's usage of external programs and scripts.
	// Lower level values are more restrictive, higher values are more permissive.
	// 0: Strictly no calling of external programs.
	// 1: (Default) Only call built-in executables such as ifconfig, ip, route, or netsh.
	// 2: Allow calling of built-in executables and user-defined scripts.
	// 3: Allow passwords to be passed to scripts via environmental variables (potentially unsafe).
	ScriptSecurityLevel *int `openvpn2:"script-security" yaml:"script_security_level,omitempty"`

	// If hostname resolve fails for --remote, retry resolve for n seconds before failing.
	ResolvRetry *string `openvpn2:"resolv-retry" yaml:"resolv_retry,omitempty"`

	// Specify the link layer address, more commonly known as the MAC address.
	// Only applied to TAP devices.
	LLAddr *string `openvpn2:"lladdr" yaml:"lladdr,omitempty"`

	// The openvpn2 executable path in the container, by default it's "openvpn"
	ExecutablePath *string `openvpn2:"-" yaml:"executable_path,omitempty" json:"executable_path,omitempty"`

	// Since there's no official openvpn2 image, so the user have to specify it explicitly.
	Image string `openvpn2:"-" yaml:"image" json:"image"`

	// Hostname of the container
	HostName *string `openvpn2:"-" yaml:"hostname,omitempty" json:"hostname,omitempty"`

	// Port mappings, in case to publish container ports to host's public network
	// Usually tcp port 1194 should be published.
	Ports map[string][]pkgdocker.DockerPortMapping `yaml:"ports,omitempty" json:"ports,omitempty"`

	// Networks to join, the network must exist, if not, one should manually create
	// the docker network using command such as `docker network create <network_name>` to create it before use.
	DockerNetworks []string `openvpn2:"-" yaml:"docker_networks,omitempty" json:"docker_networks,omitempty"`

	// Path to the TLS cert file in the host
	// By default, it would be bind mount to /etc/openvpn/certs/cert.pem in the container
	// Note that HostTLSCertFile can also be a URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	HostTLSCertFile string `openvpn2:"-" yaml:"host_tls_cert_file" json:"host_tls_cert_file"`

	// Path to the TLS cert key file in the host
	// By default, it would be bind mount to /etc/openvpn/certs/key.pem in the container
	// Note that HostTLSKeyFile can also be a URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	HostTLSKeyFile string `openvpn2:"-" yaml:"host_tls_key_file" json:"host_tls_key_file"`

	// Path to the DH PEM file in the host, only needed when in server mode
	// By default, it would be bind mount to /etc/openvpn/certs/dh.pem in the container (when provided)
	// Note that HostDHPEMFile can also be a URL, the URL can be a regular file path, or a HTTP/HTTPS URL.
	HostDHPEMFile *string `openvpn2:"-" yaml:"host_dh_pem_file,omitempty" json:"host_dh_pem_file,omitempty"`

	AutoRemove *bool `openvpn2:"-" yaml:"autoremove,omitempty" json:"autoremove,omitempty"`

	TTY *bool `openvpn2:"-" yaml:"tty,omitempty" json:"tty,omitempty"`

	OpenStdin *bool `openvpn2:"-" yaml:"stdin_open,omitempty" json:"stdin_open,omitempty"`
}

type OpenVPN2ConfigurationList []OpenVPN2Instance

type OpenVPN2InterfaceCanceller struct {
	ContainerName string
	InterfaceName string
}
