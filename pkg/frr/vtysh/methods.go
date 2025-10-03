package vtysh

import (
	"context"

	pkgfrrvtyshcontainer "github.com/internetworklab/netapply/pkg/frr/vtysh/container"
	pkgfrrvtyshhost "github.com/internetworklab/netapply/pkg/frr/vtysh/host"
)

func GetVtyshConfigWriter(ctx context.Context, containerName *string) (VtyshConfigWriter, error) {
	if containerName == nil {
		p := pkgfrrvtyshhost.DefaultVtyshPath
		return pkgfrrvtyshhost.NewHostVtyshConfigWriter(&p), nil
	}

	// If containerName is nil, treat it as the host netns
	p := pkgfrrvtyshcontainer.DefaultVtyshPath
	return pkgfrrvtyshcontainer.NewContainerVtyshConfigWriter(ctx, *containerName, &p)
}
