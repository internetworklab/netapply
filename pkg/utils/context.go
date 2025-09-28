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

func StatefulDirFromCtx(ctx context.Context) (string, error) {
	statefulDir, ok := ctx.Value(ctxKeyStatefulDir).(string)
	if !ok {
		return "", fmt.Errorf("stateful dir is not set in context")
	}
	return statefulDir, nil
}
