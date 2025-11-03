package stub

import (
	"context"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
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
