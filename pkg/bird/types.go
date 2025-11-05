package bird

type BirdBGPConfigurationList struct {
	ReloaderShellCommand  string        `yaml:"reloader_shell_command" json:"reloader_shell_command" bson:"reloader_shell_command"`
	TargetConfigDirectory string        `yaml:"target_config_directory" json:"target_config_directory" bson:"target_config_directory"`
	EBGPProtocols         []BGPProtocol `yaml:"ebgp_protocols" json:"ebgp_protocols" bson:"ebgp_protocols"`
}

type BGPProtocol struct {
	Name         string  `yaml:"name" json:"name" bson:"name"`
	Template     *string `yaml:"template,omitempty" json:"template,omitempty" bson:"template,omitempty"`
	Interface    *string `yaml:"interface,omitempty" json:"interface,omitempty" bson:"interface,omitempty"`
	LocalAddress *string `yaml:"local_address,omitempty" json:"local_address,omitempty" bson:"local_address,omitempty"`
	PeerAddress  *string `yaml:"peer_address,omitempty" json:"peer_address,omitempty" bson:"peer_address,omitempty"`
	LocalASN     *string `yaml:"local_asn,omitempty" json:"local_asn,omitempty" bson:"local_asn,omitempty"`
	PeerASN      *string `yaml:"peer_asn,omitempty" json:"peer_asn,omitempty" bson:"peer_asn,omitempty"`
	PeerExternal *bool   `yaml:"peer_external,omitempty" json:"peer_external,omitempty" bson:"peer_external,omitempty"`
	PeerInternal *bool   `yaml:"peer_internal,omitempty" json:"peer_internal,omitempty" bson:"peer_internal,omitempty"`

	// For storing in database, distinguish which node the resource belongs to.
	Node *string `yaml:"node,omitempty" json:"node,omitempty" bson:"node,omitempty"`

	// For storing in database, the unique ID to distinguish the resource in the global scope.
	ResourceID *string `yaml:"resource_id,omitempty" json:"resource_id,omitempty" bson:"resource_id,omitempty"`

	// To support soft-deletion.
	Deleted bool `yaml:"deleted,omitempty" json:"deleted,omitempty" bson:"deleted,omitempty"`

	Reloader        string `yaml:"-" json:"-" bson:"-"`
	ConfigDirectory string `yaml:"-" json:"-" bson:"-"`
}

const patternWildCard = "*"
const patternAnySequence = "**"

const ConfigExtension = ".conf"
