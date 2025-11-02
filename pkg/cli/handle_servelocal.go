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

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

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

	if cmd.BindUnixSocket == "" {
		return fmt.Errorf("bind unix socket is not set")
	}

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

	uri := "mongodb://localhost:27017"
	envMongoDBURI := os.Getenv("MONGODB_URI")
	if envMongoDBURI != "" {
		uri = envMongoDBURI
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	defer client.Disconnect(context.TODO())

	muxer := http.NewServeMux()
	muxer.Handle("/collections/", pkghandler.NewCollectionHandler(client))
	muxer.Handle("/resources/", pkghandler.NewResourceHandler(ctx))
	muxer.Handle("/basicinfo/", pkghandler.NewBasicInfoHandler(ctx))

	server := &http.Server{
		Handler: muxer,
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
