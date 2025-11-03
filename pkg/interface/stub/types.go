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
	GetNetnsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error)
	GetInterfaceName() string
}
