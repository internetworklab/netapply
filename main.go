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

	"encoding/json"
	"net/http"

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
	Up                    UpCmd         `cmd:"" help:"Start the service with the specified configuration"`
	Down                  DownCmd       `cmd:"" help:"Stop all containers associated with the service"`
	ServeLocal            ServeLocalCmd `cmd:"" help:"Serving as a local configurator"`
	ServiceName           string        `required:"" help:"Name of the service" short:"s"`
	Node                  string        `help:"Name of the node to start" short:"n"`
	TLSTrustedCACert      string        `help:"Path to trusted CA certificate file for TLS" type:"path"`
	TLSClientCert         string        `help:"Path to client certificate file for TLS" type:"path"`
	TLSClientKey          string        `help:"Path to client private key file for TLS" type:"path"`
	HTTPBasicAuthUsername string        `help:"Username for HTTP basic authentication"`
	HTTPBasicAuthPassword string        `help:"Password for HTTP basic authentication"`
}

type UpCmd struct {
	Config string `required:"" help:"Path to the configuration file"`
}

type DownCmd struct {
}

type ServeLocalCmd struct {
	BindUnixSocket string `help:"Path to the unix socket to bind" type:"path"`
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
	ctx = pkgutils.SetServiceNameInCtx(ctx, globalCLIConfig.ServiceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)
	ctx = pkgutils.SetClientAuthInCtx(ctx, clientAuth)
	return ctx, nil
}

// Run method for UpCmd
func (cmd *UpCmd) Run(globalCliConfigAny interface{}) error {
	ctx := context.Background()
	globalCLIConfig := globalCliConfigAny.(*CLI)
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
	log.Printf("Setting up service %s on node %s ...", globalCLIConfig.ServiceName, globalCLIConfig.Node)
	if err := nodeConfig.Up(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// Run method for DownCmd
func (cmd *DownCmd) Run(globalConfig interface{}) error {
	globalCLIConfig := globalConfig.(*CLI)
	serviceName := globalCLIConfig.ServiceName

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
	if err := down(ctx); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	log.Printf("Service '%s' stopped successfully\n", serviceName)
	return nil
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func respondError(w http.ResponseWriter, err error, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{Error: err.Error()})
}

func (cmd *ServeLocalCmd) Run(globalConfig interface{}) error {

	globalCLIConfig := globalConfig.(*CLI)
	ctx, err := initCtx(context.Background(), globalCLIConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize context: %w", err)
	}

	log.Printf("Serving as a local configurator on %s\n", cmd.BindUnixSocket)
	return nil

	server := &http.Server{
		Addr: cmd.BindUnixSocket,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Received request: %s %s", r.Method, r.URL.Path)

			nodeConfig := new(pkgmodels.NodeConfig)

			contentType := r.Header.Get("Content-Type")
			var err error

			if strings.HasPrefix(contentType, "application/yaml") {
				err = yaml.NewDecoder(r.Body).Decode(nodeConfig)
			} else if strings.HasPrefix(contentType, "application/json") {
				err = json.NewDecoder(r.Body).Decode(nodeConfig)
			} else {
				err = json.NewDecoder(r.Body).Decode(nodeConfig)
			}

			if err != nil {
				respondError(w, err, http.StatusBadRequest)
				return
			}

			if err := nodeConfig.Up(ctx); err != nil {
				respondError(w, err, http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
		}),
	}

	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to listen and serve: %w", err)
	}

	return nil
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)
	err := ctx.Run(&cli)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
