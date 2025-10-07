package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v3"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func down(ctx context.Context) error {
	serviceName, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	containerList, err := pkgdocker.NewContainerListFromServiceName(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("failed to get container list from service name: %w", err)
	}

	for _, cont := range containerList.GetContainers() {
		if err := pkgdocker.StopAndRemoveContainer(ctx, pkgutils.NormalizeContainerName(cont.Names[0])); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop container %s: %v\n", cont.Names[0], err)
			continue
		}
		log.Printf("Container %s is stopped", cont.Names[0])
	}

	return nil
}

// getGlobalConfig reads configuration from either a file, stdin, or HTTP(S) endpoint
// path: file path, "-" for stdin, or HTTP(S) URL
// config: pointer to GlobalConfig struct to populate
// tlsConfig: TLS configuration for HTTPS requests (can be nil for default)
func getGlobalConfig(configPath string, clientAuth *pkgutils.ClientAuth) error {
	var reader io.ReadCloser
	var err error

	var tlsConfig *tls.Config
	if strings.HasPrefix(configPath, "https://") {
		tlsConfig, err = pkgutils.GetTLSConfig(clientAuth.TLSTrustedCACertFile, clientAuth.TLSClientCertFile, clientAuth.TLSClientKeyFile)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
	}

	readerConfig := &pkgutils.URLReaderTransportOptions{
		TLSConfig: tlsConfig,
		Username:  clientAuth.HTTPBasicAuthUsername,
		Password:  clientAuth.HTTPBasicAuthPassword,
	}

	reader, err = pkgutils.NewURLReader(configPath, readerConfig)
	if err != nil {
		return fmt.Errorf("failed to create URL reader: %w", err)
	}

	defer reader.Close()

	// Parse YAML configuration
	config := new(pkgmodels.GlobalConfig)
	if err := yaml.NewDecoder(reader).Decode(config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	return nil
}

// CLI structure for Kong
type CLI struct {
	Up   UpCmd   `cmd:"" help:"Start the service with the specified configuration"`
	Down DownCmd `cmd:"" help:"Stop all containers associated with the service"`
}

type UpCmd struct {
	Config                string `required:"" help:"Path to the configuration file" type:"path"`
	ServiceName           string `required:"" help:"Name of the service" short:"s"`
	Node                  string `required:"" help:"Name of the node to start" short:"n"`
	TLSTrustedCACert      string `help:"Path to trusted CA certificate file for TLS" type:"path"`
	TLSClientCert         string `help:"Path to client certificate file for TLS" type:"path"`
	TLSClientKey          string `help:"Path to client private key file for TLS" type:"path"`
	HTTPBasicAuthUsername string `help:"Username for HTTP basic authentication"`
	HTTPBasicAuthPassword string `help:"Password for HTTP basic authentication"`
}

type DownCmd struct {
	ServiceName string `required:"" help:"Name of the service" short:"s"`
}

// Run method for UpCmd
func (cmd *UpCmd) Run() error {
	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	clientAuth := &pkgutils.ClientAuth{
		TLSClientCertFile:     cmd.TLSClientCert,
		TLSClientKeyFile:      cmd.TLSClientKey,
		TLSTrustedCACertFile:  cmd.TLSTrustedCACert,
		HTTPBasicAuthUsername: cmd.HTTPBasicAuthUsername,
		HTTPBasicAuthPassword: cmd.HTTPBasicAuthPassword,
	}

	// Set up context with service name and docker client
	ctx = pkgutils.SetServiceNameInCtx(ctx, cmd.ServiceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)
	ctx = pkgutils.SetClientAuthInCtx(ctx, clientAuth)

	// Read and parse the configuration
	globalConfig := new(pkgmodels.GlobalConfig)
	if err := getGlobalConfig(cmd.Config, clientAuth); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get the specified node configuration
	nodeConfig, ok := globalConfig.Nodes[cmd.Node]
	if !ok {
		return fmt.Errorf("node '%s' not found in configuration", cmd.Node)
	}

	// Start the service
	log.Printf("Setting up service %s on node %s ...", cmd.ServiceName, cmd.Node)
	if err := nodeConfig.Up(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// Run method for DownCmd
func (cmd *DownCmd) Run() error {
	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Set up context with service name and docker client
	ctx = pkgutils.SetServiceNameInCtx(ctx, cmd.ServiceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	// Stop all containers associated with the service
	if err := down(ctx); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	log.Printf("Service '%s' stopped successfully\n", cmd.ServiceName)
	return nil
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)
	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
