//go:generate sh -c "echo CommitHash: $(git rev-parse HEAD) > commit.txt"
//go:generate sh -c "echo BuildTime: $(date --utc --iso-8601=seconds) >> commit.txt"
//go:generate sh -c "echo RevisionOrTag: $(git describe --exact-match --tags) >> commit.txt"
//go:generate sh -c "echo GoVersion: $(go version) >> commit.txt"
//go:generate sh -c "echo Uname-srvm: $(uname -srvm) >> commit.txt"
//go:generate sh -c "echo OfficialSite: https://github.com/internetworklab/netapply >> commit.txt"
//go:generate sh -c "echo License: MIT >> commit.txt"
//go:generate sh -c "echo 'Copyright: Copyright (c) 2025 duststars' >> commit.txt"

package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v3"

	"net"
	"net/http"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkghandler "github.com/internetworklab/netapply/pkg/handler"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func handleCleanUp(ctx context.Context) error {
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
func getGlobalConfig(configPath string, clientAuth *pkgutils.ClientAuth) (*pkgmodels.GlobalConfig, error) {

	var reader io.ReadCloser
	var err error

	var tlsConfig *tls.Config
	if strings.HasPrefix(configPath, "https://") {
		tlsConfig, err = pkgutils.GetTLSConfig(clientAuth.TLSTrustedCACertFile, clientAuth.TLSClientCertFile, clientAuth.TLSClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
	}

	readerConfig := &pkgutils.URLReaderTransportOptions{
		TLSConfig: tlsConfig,
		Username:  clientAuth.HTTPBasicAuthUsername,
		Password:  clientAuth.HTTPBasicAuthPassword,
	}

	reader, err = pkgutils.NewURLReader(configPath, readerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create URL reader: %w", err)
	}

	defer reader.Close()

	// Parse YAML configuration
	config := new(pkgmodels.GlobalConfig)
	if err := yaml.NewDecoder(reader).Decode(config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
}

// CLI structure for Kong
type CLI struct {
	Up         UpCmd         `cmd:"" help:"Start the service with the specified configuration"`
	Down       DownCmd       `cmd:"" help:"Stop all containers associated with the service"`
	ServeLocal ServeLocalCmd `cmd:"" help:"Serving as a local configurator"`
	Version    VersionCmd    `cmd:"" help:"Show the version of the program"`

	Node                  string `help:"Name of the node to start" short:"n"`
	TLSTrustedCACert      string `help:"Path to trusted CA certificate file for TLS" type:"path"`
	TLSClientCert         string `help:"Path to client certificate file for TLS" type:"path"`
	TLSClientKey          string `help:"Path to client private key file for TLS" type:"path"`
	HTTPBasicAuthUsername string `help:"Username for HTTP basic authentication"`
	HTTPBasicAuthPassword string `help:"Password for HTTP basic authentication"`
	VersionMetadata       map[string]string
}

type VersionCmd struct {
	CommitHash string
}

func (cmd *VersionCmd) Run(globalCLIConfig *CLI) error {
	pairs := make([][]string, 0)
	for key, value := range globalCLIConfig.VersionMetadata {
		pair := make([]string, 0)
		pair = append(pair, key)
		pair = append(pair, value)
		pairs = append(pairs, pair)
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i][0] < pairs[j][0]
	})
	for _, pair := range pairs {
		fmt.Printf("%s: %s\n", pair[0], pair[1])
	}

	return nil
}

type UpCmd struct {
	Config      string `required:"" help:"Path to the configuration file"`
	ServiceName string `required:"" help:"Name of the service" short:"s"`
}

type DownCmd struct {
	ServiceName string `required:"" help:"Name of the service" short:"s"`
}

type ServeLocalCmd struct {
	BindUnixSocket string `help:"Path to the unix socket to bind" type:"path"`
	ServiceName    string `required:"" help:"Name of the service" short:"s"`
}

func initCtx(ctx context.Context, globalCLIConfig *CLI) (context.Context, error) {
	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ctx, fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	clientAuth := &pkgutils.ClientAuth{
		TLSClientCertFile:     globalCLIConfig.TLSClientCert,
		TLSClientKeyFile:      globalCLIConfig.TLSClientKey,
		TLSTrustedCACertFile:  globalCLIConfig.TLSTrustedCACert,
		HTTPBasicAuthUsername: globalCLIConfig.HTTPBasicAuthUsername,
		HTTPBasicAuthPassword: globalCLIConfig.HTTPBasicAuthPassword,
	}

	// Set up context with service name and docker client
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)
	ctx = pkgutils.SetClientAuthInCtx(ctx, clientAuth)
	return ctx, nil
}

// Run method for UpCmd
func (cmd *UpCmd) Run(globalCLIConfig *CLI) error {
	ctx := context.Background()
	ctx, err := initCtx(ctx, globalCLIConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize context: %w", err)
	}
	clientAuth, _ := pkgutils.ClientAuthFromCtx(ctx)

	// Read and parse the configuration
	var globalConfig *pkgmodels.GlobalConfig
	if globalConfig, err = getGlobalConfig(cmd.Config, clientAuth); err != nil || globalConfig == nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get the specified node configuration
	nodeConfig, ok := globalConfig.Nodes[globalCLIConfig.Node]
	if !ok {
		return fmt.Errorf("node '%s' not found in configuration", globalCLIConfig.Node)
	}

	// Start the service
	log.Printf("Setting up service %s on node %s ...", cmd.ServiceName, globalCLIConfig.Node)
	ctx = pkgutils.SetServiceNameInCtx(ctx, cmd.ServiceName)
	if err := nodeConfig.Up(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// Run method for DownCmd
func (cmd *DownCmd) Run(globalCLIConfig *CLI) error {

	serviceName := cmd.ServiceName

	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Set up context with service name and docker client
	ctx = pkgutils.SetServiceNameInCtx(ctx, serviceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	// Stop all containers associated with the service
	if err := handleCleanUp(ctx); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	log.Printf("Service '%s' stopped successfully\n", serviceName)
	return nil
}

func (cmd *ServeLocalCmd) Run(globalCLIConfig *CLI) error {
	ctx, err := initCtx(context.Background(), globalCLIConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize context: %w", err)
	}
	ctx = pkgutils.SetServiceNameInCtx(ctx, cmd.ServiceName)
	ctx = pkgutils.SetVersionMetadataInCtx(ctx, globalCLIConfig.VersionMetadata)
	ctx = pkgutils.SetNodeNameInCtx(ctx, globalCLIConfig.Node)
	ctx = pkgutils.SetStartedAtInCtx(ctx, uint64(time.Now().Unix()))
	ctx = pkgutils.SetUnixSocketPathInCtx(ctx, cmd.BindUnixSocket)

	log.Printf("Serving as a local configurator on %s\n", cmd.BindUnixSocket)

	listener, err := net.Listen("unix", cmd.BindUnixSocket)
	if err != nil {
		return fmt.Errorf("failed to create listener on %s: %w", cmd.BindUnixSocket, err)
	}
	defer func() {
		_, err := os.Stat(cmd.BindUnixSocket)
		if err == nil {
			log.Printf("unix socket %s is still exists, removing it\n", cmd.BindUnixSocket)
			log.Printf("Cleaning up unix socket %s\n", cmd.BindUnixSocket)
			if err := os.Remove(cmd.BindUnixSocket); err != nil {
				log.Printf("failed to remove unix socket %s: %v", cmd.BindUnixSocket, err)
			}
			log.Printf("removed unix socket %s\n", cmd.BindUnixSocket)
		}
	}()

	handlerRouter := pkghandler.NewRouterHandler(ctx)

	server := &http.Server{
		Handler: handlerRouter,
	}

	serverErrCh := make(chan error)
	go func() {
		log.Printf("Starting server on %s\n", cmd.BindUnixSocket)
		serverErrCh <- server.Serve(listener)
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	clearingCh := make(chan interface{})
	go func() {
		log.Println("Exiting signal handler is in-position")
		<-sigs
		log.Println("Exiting...")

		log.Println("Shutting down server...")
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("failed to shutdown server: %v", err)
		}

		close(clearingCh)
	}()

	<-clearingCh

	err = <-serverErrCh
	if err != nil {
		if err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	}

	log.Println("Server is shut down")

	return nil
}

//go:embed commit.txt
var CommitHash string

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)
	cli.VersionMetadata = pkgutils.ParseKVPairs(":", CommitHash)
	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
