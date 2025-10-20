package wgplan

type WGNode struct {
	ListenPortBase *int    `yaml:"listen_port_base,omitempty"`
	EndpointHost   *string `yaml:"endpoint_host,omitempty"`
}

type WGConnection struct {
	SelfPrivateKey     *string `yaml:"self_private_key,omitempty"`
	SelfPrivateKeyFile *string `yaml:"self_private_key_file,omitempty"`

	SelfPublicKey string `yaml:"self_public_key,omitempty"`

	PeerPublicKey string `yaml:"peer_public_key,omitempty"`

	SelfListenPort *int `yaml:"self_listen_port,omitempty"`

	PeerEndpointHost *string `yaml:"peer_endpoint_host,omitempty"`
	PeerEndpointPort *int    `yaml:"peer_endpoint_port,omitempty"`

	ConnectionID *string `yaml:"connection_id,omitempty"`
}

type WGPlan struct {
	Nodes              map[string]WGNode                   `yaml:"nodes"`
	Connections        map[string]map[string]*WGConnection `yaml:"connections"`
	IndexedConnections map[string]*WGConnection            `yaml:"indexed_connections,omitempty"`
}
