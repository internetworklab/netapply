package vtysh

import (
	"context"

	container "example.com/connector/pkg/vtysh/container"
	host "example.com/connector/pkg/vtysh/host"
)

func GetVtyshConfigWriter(ctx context.Context, containerName *string) (VtyshConfigWriter, error) {
	if containerName == nil {
		return host.NewHostVtyshConfigWriter(), nil
	}

	// If containerName is nil, treat it as the host netns
	return container.NewContainerVtyshConfigWriter(*containerName), nil
}
