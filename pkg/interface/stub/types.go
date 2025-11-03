package stub

import (
	"context"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
)

type StubInterfaceCanceller struct {
	NetnsInfo     *pkgnetns.NetNsInfo
	InterfaceName string
	Type          string
}

type StubNetlinkInterface interface {
	GetType() string
	GetInterfaceName() string
	GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error)
}

type ContainerizableResource interface {
	GetDockerContainerName(ctx context.Context) *string
	GetPodmanContainerName(ctx context.Context) *string
	GetNetNsPath(ctx context.Context) *string
}

type StubNetlinkInterfaceList interface {
	GetType() string
	GetProvisioners() []pkgreconcile.ResourceProvisioner
	GetContainers(ctx context.Context) ([]pkgnetns.NetNsInfo, error)
}
