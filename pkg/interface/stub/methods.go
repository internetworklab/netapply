package stub

import (
	"context"
	"fmt"
	"strings"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	"github.com/vishvananda/netlink"
)

func (stubInterfaceCanceller *StubInterfaceCanceller) GetInterfaceName() string {
	return stubInterfaceCanceller.InterfaceName
}

func (stubInterfaceCanceller *StubInterfaceCanceller) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return stubInterfaceCanceller.NetnsInfo, nil
}

func (stubInterfaceCanceller *StubInterfaceCanceller) GetType() string {
	return stubInterfaceCanceller.Type
}

func (stubInterfaceCanceller *StubInterfaceCanceller) Cancel(ctx context.Context) error {
	if stubInterfaceCanceller.InterfaceName == "lo" {
		// skip special interfaces such as "lo"
		return nil
	}

	if strings.HasPrefix(stubInterfaceCanceller.InterfaceName, "eth") || strings.HasPrefix(stubInterfaceCanceller.InterfaceName, "lo") {
		return nil
	}

	return pkgnetns.WithNsHandle(ctx, stubInterfaceCanceller.NetnsInfo, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(stubInterfaceCanceller.InterfaceName)
		if err == nil && link != nil {
			// in case that the interface might be already deleted, we don't need to delete it again
			// and such case is not considered as an error (for example, for a veth pair, another end will immediately get deleted once one end is deleted)
			if err := handle.LinkDel(link); err != nil {
				return fmt.Errorf("failed to delete link: %w", err)
			}
		}

		return nil
	})
}

func CheckExist(ctx context.Context, nlIf StubNetlinkInterface) (bool, error) {
	type result struct {
		Exist bool
	}
	res := new(result)
	netnsInfo, err := nlIf.GetNetNsInfo(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get netns info: %w", err)
	}

	err = pkgnetns.WithNsHandleSafe(ctx, netnsInfo, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(nlIf.GetInterfaceName())
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				return nil
			}
			return fmt.Errorf("failed to get link: %w", err)
		}
		if link != nil {
			res.Exist = true
		}
		return nil
	})

	return res.Exist, err
}

type ContainerizableResource interface {
	GetDockerContainerName(ctx context.Context) *string
	GetPodmanContainerName(ctx context.Context) *string
	GetNetNsPath(ctx context.Context) *string
}

func GetNetNsInfo(ctx context.Context, nlIf ContainerizableResource) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}
