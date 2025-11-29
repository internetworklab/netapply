package utils

import (
	"context"
	"fmt"

	"github.com/docker/docker/client"
)

type CtxKey string

const ctxKeyDockerCli CtxKey = "docker_cli"
const ctxKeyServiceName CtxKey = "service_name"
const ctxKeyStatefulDir CtxKey = "stateful_dir"
const CtxKeyClientAuth CtxKey = "client_auth"
const CtxKeyVersionMetadata CtxKey = "version_metadata"
const CtxKeyNodeName CtxKey = "node_name"
const CtxKeyStartedAt CtxKey = "started_at"
const CtxKeyUnixSocketPath CtxKey = "unix_socket_path"
const CtxKeyResolverEndpoint CtxKey = "resolver_endpoint"
const CtxKeyBirdBGPConfigDir CtxKey = "bird_bgp_config_dir"
const CtxKeyBirdControlSocket CtxKey = "bird_control_socket"
const CtxKeyV6Available CtxKey = "v6_available"

type ClientAuth struct {
	TLSClientCertFile     string
	TLSClientKeyFile      string
	TLSTrustedCACertFile  string
	HTTPBasicAuthUsername string
	HTTPBasicAuthPassword string
}

func UnixSocketPathFromCtx(ctx context.Context) (string, error) {
	unixSocketPath, ok := ctx.Value(CtxKeyUnixSocketPath).(string)
	if !ok {
		return "", fmt.Errorf("unix socket path is not set in context")
	}
	return unixSocketPath, nil
}

func V6AvailableFromCtx(ctx context.Context) (bool, error) {
	v6Available, ok := ctx.Value(CtxKeyV6Available).(bool)
	if !ok {
		return false, nil
	}
	return v6Available, nil
}

func SetV6AvailableInCtx(ctx context.Context, v6Available bool) context.Context {
	return context.WithValue(ctx, CtxKeyV6Available, v6Available)
}

func SetUnixSocketPathInCtx(ctx context.Context, unixSocketPath string) context.Context {
	return context.WithValue(ctx, CtxKeyUnixSocketPath, unixSocketPath)
}

func StartedAtFromCtx(ctx context.Context) (uint64, error) {
	startedAt, ok := ctx.Value(CtxKeyStartedAt).(uint64)
	if !ok {
		return 0, fmt.Errorf("started at is not set in context")
	}
	return startedAt, nil
}

func SetStartedAtInCtx(ctx context.Context, startedAt uint64) context.Context {
	return context.WithValue(ctx, CtxKeyStartedAt, startedAt)
}

func NodeNameFromCtx(ctx context.Context) (string, error) {
	nodeName, ok := ctx.Value(CtxKeyNodeName).(string)
	if !ok {
		return "", fmt.Errorf("node name is not set in context")
	}
	return nodeName, nil
}

func SetNodeNameInCtx(ctx context.Context, nodeName string) context.Context {
	return context.WithValue(ctx, CtxKeyNodeName, nodeName)
}

func VersionMetadataFromCtx(ctx context.Context) (map[string]string, error) {
	versionMetadata, ok := ctx.Value(CtxKeyVersionMetadata).(map[string]string)
	if !ok {
		return nil, fmt.Errorf("version metadata is not set in context")
	}
	return versionMetadata, nil
}

func SetVersionMetadataInCtx(ctx context.Context, versionMetadata map[string]string) context.Context {
	return context.WithValue(ctx, CtxKeyVersionMetadata, versionMetadata)
}

func ClientAuthFromCtx(ctx context.Context) (*ClientAuth, error) {
	clientAuth, ok := ctx.Value(CtxKeyClientAuth).(*ClientAuth)
	if !ok {
		return nil, fmt.Errorf("client auth is not set in context")
	}
	return clientAuth, nil
}

func DockerCliFromCtx(ctx context.Context) (*client.Client, error) {
	cli, ok := ctx.Value(ctxKeyDockerCli).(*client.Client)
	if !ok {
		return nil, fmt.Errorf("docker cli is not set in context")
	}

	return cli, nil
}

func BirdBGPConfigDirFromCtx(ctx context.Context) (string, error) {
	configDir, ok := ctx.Value(CtxKeyBirdBGPConfigDir).(string)
	if !ok {
		return "", fmt.Errorf("bird bgp config directory is not set in context")
	}
	return configDir, nil
}

func BirdControlSocketFromCtx(ctx context.Context) (string, error) {
	controlSocket, ok := ctx.Value(CtxKeyBirdControlSocket).(string)
	if !ok {
		return "", fmt.Errorf("bird control socket is not set in context")
	}
	return controlSocket, nil
}

func SetBirdControlSocketInCtx(ctx context.Context, controlSocket string) context.Context {
	return context.WithValue(ctx, CtxKeyBirdControlSocket, controlSocket)
}

func SetDockerCliInCtx(ctx context.Context, cli *client.Client) context.Context {
	return context.WithValue(ctx, ctxKeyDockerCli, cli)
}

func SetServiceNameInCtx(ctx context.Context, serviceName string) context.Context {
	return context.WithValue(ctx, ctxKeyServiceName, serviceName)
}

func SetStatefulDirInCtx(ctx context.Context, statefulDir string) context.Context {
	return context.WithValue(ctx, ctxKeyStatefulDir, statefulDir)
}

func SetClientAuthInCtx(ctx context.Context, clientAuth *ClientAuth) context.Context {
	return context.WithValue(ctx, CtxKeyClientAuth, clientAuth)
}

func StatefulDirFromCtx(ctx context.Context) (string, error) {
	statefulDir, ok := ctx.Value(ctxKeyStatefulDir).(string)
	if !ok {
		return "", fmt.Errorf("stateful dir is not set in context")
	}
	return statefulDir, nil
}

func SetResolverEndpointInCtx(ctx context.Context, resolverEndpoint string) context.Context {
	return context.WithValue(ctx, CtxKeyResolverEndpoint, resolverEndpoint)
}

func SetBirdBGPConfigDirInCtx(ctx context.Context, configDir string) context.Context {
	return context.WithValue(ctx, CtxKeyBirdBGPConfigDir, configDir)
}

func ResolverEndpointFromCtx(ctx context.Context) (string, error) {
	resolverEndpoint, ok := ctx.Value(CtxKeyResolverEndpoint).(string)
	if !ok {
		return "", nil
	}
	return resolverEndpoint, nil
}
