package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v3"

	pkgdocker "example.com/connector/pkg/docker"
	pkgmodels "example.com/connector/pkg/models"
	pkgutils "example.com/connector/pkg/utils"
)

const (
	OVTagFlagEmptyKey string = "emptykey"
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

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	for _, cont := range containerList.GetContainers() {
		if err := cli.ContainerStop(ctx, cont.ID, container.StopOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop container %s: %v\n", cont.Names[0], err)
			continue
		}
		labelsStr := ""
		if cont.Labels != nil {
			v, err := json.Marshal(cont.Labels)
			if err != nil {
				log.Fatalf("failed to marshal labels for %s: %v", cont.Names[0], err)
			}
			labelsStr = string(v)
		}
		log.Printf("Container %s %s is stopped", cont.Names[0], labelsStr)
	}

	return nil
}

// getGlobalConfig reads configuration from either a file, stdin, or HTTP(S) endpoint
// path: file path, "-" for stdin, or HTTP(S) URL
// config: pointer to GlobalConfig struct to populate
// tlsConfig: TLS configuration for HTTPS requests (can be nil for default)
func getGlobalConfig(cmd *UpCmd, config *pkgmodels.GlobalConfig) error {
	var reader io.Reader
	var err error

	path := cmd.Config

	if path == "-" {
		log.Println("Reading configuration from stdin ...")
		// Read from stdin
		reader = os.Stdin
	} else if strings.HasPrefix(path, "https://") {
		log.Printf("Reading configuration from HTTPS endpoint %s ...", path)

		tlsConfig, err := getTLSConfig(cmd.TLSTrustedCACert, cmd.TLSClientCert, cmd.TLSClientKey)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}

		// Read from HTTPS endpoint
		reader, err = fetchHTTPConfig(path, tlsConfig, cmd.HTTPBasicAuthUsername, cmd.HTTPBasicAuthPassword)
		if err != nil {
			return fmt.Errorf("failed to fetch HTTPS config from '%s': %w", path, err)
		}
	} else if strings.HasPrefix(path, "http://") {
		log.Printf("Reading configuration from HTTP endpoint %s ...", path)

		// Read from HTTP endpoint
		reader, err = fetchHTTPConfig(path, nil, cmd.HTTPBasicAuthUsername, cmd.HTTPBasicAuthPassword)
		if err != nil {
			return fmt.Errorf("failed to fetch HTTP config from '%s': %w", path, err)
		}
	} else {
		log.Printf("Reading configuration from file %s ...", path)

		// Read from file
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open config file '%s': %w", path, err)
		}
		defer file.Close()
		reader = file
	}

	// Parse YAML configuration
	if err := yaml.NewDecoder(reader).Decode(config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	return nil
}

// fetchHTTPConfig fetches configuration from an HTTP(S) endpoint
func fetchHTTPConfig(url string, tlsConfig *tls.Config, username, password string) (io.Reader, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	request.Header.Set("Accept", "application/yaml")

	// Add basic authentication if credentials are provided
	if username != "" && password != "" {
		request.SetBasicAuth(username, password)
	}

	// Make HTTP request
	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	// Read response body into memory
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return strings.NewReader(string(body)), nil
}

// getTLSConfig creates a TLS configuration from the provided certificate files
func getTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	// If no TLS parameters are provided, return nil (use default TLS config)
	if caCertPath == "" && clientCertPath == "" && clientKeyPath == "" {
		return nil, nil
	}

	config := &tls.Config{}

	// Load CA certificate if provided
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from '%s': %w", caCertPath, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from '%s'", caCertPath)
		}
		config.RootCAs = caCertPool
	}

	// Load client certificate and key if both are provided
	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate pair (cert: '%s', key: '%s'): %w", clientCertPath, clientKeyPath, err)
		}
		config.Certificates = []tls.Certificate{cert}
	} else if clientCertPath != "" || clientKeyPath != "" {
		// If only one of client cert or key is provided, that's an error
		return nil, fmt.Errorf("both client certificate and key must be provided together")
	}

	return config, nil
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

	// Set up context with service name and docker client
	ctx = pkgutils.SetServiceNameInCtx(ctx, cmd.ServiceName)
	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	// Read and parse the configuration
	globalConfig := new(pkgmodels.GlobalConfig)
	if err := getGlobalConfig(cmd, globalConfig); err != nil {
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
