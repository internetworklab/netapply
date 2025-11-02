package cli

import (
	"context"
	"fmt"
	"log"

	pkgmodels "github.com/internetworklab/netapply/pkg/models"
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
	var nodecfg *pkgmodels.NodeConfig
	if nodecfg, err = getnodecfg(cmd.Config, clientAuth); err != nil || nodecfg == nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Start the service
	log.Printf("Setting up service %s on node %s ...", cmd.ServiceName, globalCLIConfig.Node)
	ctx = pkgutils.SetServiceNameInCtx(ctx, cmd.ServiceName)
	if err := nodecfg.Up(ctx, cmd.Delete); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}
