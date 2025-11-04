package bird

import (
	"context"
	"fmt"
)

func WithBirdBGPConfigDirectory(ctx context.Context, configDirectory string) context.Context {
	return context.WithValue(ctx, CtxKeyBirdBGPConfigDirectory, configDirectory)
}

func WithBirdBGPReloaderShellCommand(ctx context.Context, reloaderShellCommand string) context.Context {
	return context.WithValue(ctx, CtxKeyBirdBGPReloaderShellCommand, reloaderShellCommand)
}

func BirdBGPConfigDirectoryFromCtx(ctx context.Context) (string, error) {
	configDirectory, ok := ctx.Value(CtxKeyBirdBGPConfigDirectory).(string)
	if !ok {
		return "", fmt.Errorf("bird bgp config directory is not set in context")
	}
	return configDirectory, nil
}

func BirdBGPReloaderShellCommandFromCtx(ctx context.Context) (string, error) {
	reloaderShellCommand, ok := ctx.Value(CtxKeyBirdBGPReloaderShellCommand).(string)
	if !ok {
		return "", fmt.Errorf("bird bgp reloader shell command is not set in context")
	}
	return reloaderShellCommand, nil
}
