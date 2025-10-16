package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/client"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"gopkg.in/yaml.v3"
)

// getnodecfg reads configuration from either a file, stdin, or HTTP(S) endpoint
// path: file path, "-" for stdin, or HTTP(S) URL
// config: pointer to GlobalConfig struct to populate
// tlsConfig: TLS configuration for HTTPS requests (can be nil for default)
func getnodecfg(configPath string, clientAuth *pkgutils.ClientAuth) (*pkgmodels.NodeConfig, error) {

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
	config := new(pkgmodels.NodeConfig)
	if err := yaml.NewDecoder(reader).Decode(config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return config, nil
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
