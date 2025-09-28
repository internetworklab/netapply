package vtysh

import (
	"context"

	container "example.com/connector/pkg/vtysh/container"
	host "example.com/connector/pkg/vtysh/host"
)

func GetVtyshConfigWriter(ctx context.Context, containerName *string) (VtyshConfigWriter, error) {
	if containerName == nil {
		p := host.DefaultVtyshPath
		return host.NewHostVtyshConfigWriter(&p), nil
	}

	// If containerName is nil, treat it as the host netns
	p := container.DefaultVtyshPath
	return container.NewContainerVtyshConfigWriter(ctx, *containerName, &p)
}
