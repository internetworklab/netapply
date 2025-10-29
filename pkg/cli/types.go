package cli

// CLI structure for Kong
type CLI struct {
	Up         UpCmd         `cmd:"" help:"Start the service with the specified configuration"`
	CleanUp    CleanUpCmd    `cmd:"" help:"Stop and remove all containers associated with the service"`
	ServeLocal ServeLocalCmd `cmd:"" help:"Serving as a long-running local configurator process"`
	Version    VersionCmd    `cmd:"" help:"Show the version of the program"`

	Node                  string `help:"Name of the node to start" short:"n"`
	TLSTrustedCACert      string `help:"Path to trusted CA certificate file for TLS" type:"path"`
	TLSClientCert         string `help:"Path to client certificate file for TLS" type:"path"`
	TLSClientKey          string `help:"Path to client private key file for TLS" type:"path"`
	HTTPBasicAuthUsername string `help:"Username for HTTP basic authentication"`
	HTTPBasicAuthPassword string `help:"Password for HTTP basic authentication"`
	VersionMetadata       map[string]string
}

type UpCmd struct {
	Config           string `required:"" help:"Path to the configuration file"`
	ServiceName      string `required:"" help:"Name of the service" short:"s"`
	OutputChangeLogs string `help:"Outputs what's just been updated to a file, in YAML format" type:"path"`
}

type CleanUpCmd struct {
	ServiceName string `required:"" help:"Name of the service" short:"s"`
}

type ServeLocalCmd struct {
	BindUnixSocket string `help:"Path to the unix socket to bind" type:"path"`
	ServiceName    string `required:"" help:"Name of the service" short:"s"`
}
