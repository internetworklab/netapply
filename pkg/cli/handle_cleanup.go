package cli

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/docker/docker/client"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
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

// Run method for DownCmd
func (cmd *CleanUpCmd) Run(globalCLIConfig *CLI) error {

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
