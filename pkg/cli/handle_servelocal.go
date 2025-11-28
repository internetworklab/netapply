package cli

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	pkghandler "github.com/internetworklab/netapply/pkg/handler"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func (cmd *ServeLocalCmd) Run(globalCLIConfig *CLI) error {
	ctx, err := initCtx(context.Background(), globalCLIConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize context: %w", err)
	}
	ctx = pkgutils.SetVersionMetadataInCtx(ctx, globalCLIConfig.VersionMetadata)
	ctx = pkgutils.SetNodeNameInCtx(ctx, globalCLIConfig.Node)
	ctx = pkgutils.SetStartedAtInCtx(ctx, uint64(time.Now().Unix()))
	ctx = pkgutils.SetUnixSocketPathInCtx(ctx, cmd.BindUnixSocket)
	ctx = pkgutils.SetResolverEndpointInCtx(ctx, cmd.ResolverEndpoint)
	ctx = pkgutils.SetV6AvailableInCtx(ctx, cmd.V6Available)

	if cmd.BindUnixSocket == "" {
		return fmt.Errorf("bind unix socket is not set")
	}

	listener, err := net.Listen("unix", cmd.BindUnixSocket)
	if err != nil {
		return fmt.Errorf("failed to create listener on %s: %w", cmd.BindUnixSocket, err)
	}
	defer func() {
		_, err := os.Stat(cmd.BindUnixSocket)
		if err == nil {
			if err := os.Remove(cmd.BindUnixSocket); err != nil {
				log.Printf("failed to remove unix socket %s: %v", cmd.BindUnixSocket, err)
			}
		}
	}()

	muxer := http.NewServeMux()
	muxer.Handle("/resources/", pkghandler.NewResourceHandler(ctx))
	muxer.Handle("/basicinfo/", pkghandler.NewBasicInfoHandler(ctx))

	server := &http.Server{
		Handler: muxer,
	}

	serverErrCh := make(chan error)
	go func() {
		log.Printf("Serving as a local configurator (node agent) on %s\n", cmd.BindUnixSocket)
		serverErrCh <- server.Serve(listener)
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigs
	log.Printf("Received signal %s, shutting down server...\n", sig.String())

	if err := server.Shutdown(context.Background()); err != nil {
		log.Printf("failed to shutdown server: %v", err)
	}

	if err := <-serverErrCh; err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}
