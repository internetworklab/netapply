package cli

import (
	"fmt"
	"context"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	"log"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

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

