package stub

import (
	"context"
	"fmt"

	pkgdocker "example.com/connector/pkg/docker"
	"github.com/vishvananda/netlink"
)

func (stubInterfaceCanceller *StubInterfaceCanceller) GetInterfaceName() string {
	return stubInterfaceCanceller.InterfaceName
}

func (stubInterfaceCanceller *StubInterfaceCanceller) GetContainerName() *string {
	return stubInterfaceCanceller.ContainerName
}

func (stubInterfaceCanceller *StubInterfaceCanceller) Cancel(ctx context.Context) error {
	if stubInterfaceCanceller.InterfaceName == "lo" {
		// skip special interfaces such as "lo"
		return nil
	}

	return pkgdocker.WithNsHandle(ctx, stubInterfaceCanceller.ContainerName, func(handle *netlink.Handle) error {
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
