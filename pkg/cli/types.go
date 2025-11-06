package cli

// CLI structure for Kong
type CLI struct {
	Up              UpCmd              `cmd:"" help:"Apply the specified configuration"`
	ServeCollection ServeCollectionCmd `cmd:"" help:"Serving as a collection manager"`
	ServeLocal      ServeLocalCmd      `cmd:"" help:"Serving as a local configurator (node agent)"`
	Version         VersionCmd         `cmd:"" help:"Show the version of the program"`

	Node                  string `help:"Name of the node to start" short:"n"`
	TLSTrustedCACert      string `help:"Path to trusted CA certificate file for TLS" type:"path"`
	TLSClientCert         string `help:"Path to client certificate file for TLS" type:"path"`
	TLSClientKey          string `help:"Path to client private key file for TLS" type:"path"`
	HTTPBasicAuthUsername string `help:"Username for HTTP basic authentication"`
	HTTPBasicAuthPassword string `help:"Password for HTTP basic authentication"`
	VersionMetadata       map[string]string
}

type UpCmd struct {
	Delete           bool   `help:"To delete the resources not presented in the configuration"`
	Config           string `required:"" help:"Path to the configuration file"`
	OutputChangeLogs string `help:"Outputs what's just been updated to a file, in YAML format" type:"path"`
}

type ServeLocalCmd struct {
	BindUnixSocket string `help:"Path to the unix socket to bind" type:"path"`
}

type ServeCollectionCmd struct {
	MongoDBURI     string `help:"URI of the MongoDB to connect to" short:"m"`
	BindUnixSocket string `help:"Path to the unix socket to bind" type:"path"`
}
