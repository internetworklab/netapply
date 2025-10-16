package utils

import (
	"context"
	"fmt"
	"os"
	"time"
)

type BasicInfo struct {
	NodeName       string
	Hostname       string
	ServiceName    string
	StartedAt      uint64
	Uptime         uint64
	UnixSocketPath string
}

func CollectBasicInfo(ctx context.Context) (*BasicInfo, error) {
	basicInfo := new(BasicInfo)

	unixSocketPath, err := UnixSocketPathFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get unix socket path from context: %w", err)
	}
	basicInfo.UnixSocketPath = unixSocketPath

	startedAt, err := StartedAtFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get started at from context: %w", err)
	}
	basicInfo.StartedAt = startedAt

	basicInfo.Uptime = uint64(time.Now().Unix()) - uint64(startedAt)

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %w", err)
	}
	basicInfo.Hostname = hostname

	nodeName, err := NodeNameFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get node name from context: %w", err)
	}
	basicInfo.NodeName = nodeName

	serviceName, err := ServiceNameFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get service name from context: %w", err)
	}
	basicInfo.ServiceName = serviceName

	return basicInfo, nil
}
