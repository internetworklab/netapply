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

type ClientAuth struct {
	TLSClientCertFile     string
	TLSClientKeyFile      string
	TLSTrustedCACertFile  string
	HTTPBasicAuthUsername string
	HTTPBasicAuthPassword string
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

func ServiceNameFromCtx(ctx context.Context) (string, error) {
	serviceName, ok := ctx.Value(ctxKeyServiceName).(string)
	if !ok {
		return "", fmt.Errorf("service name is not set in context")
	}
	return serviceName, nil
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
