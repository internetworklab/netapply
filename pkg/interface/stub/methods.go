package stub

import (
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	context "context"
	netlink "github.com/vishvananda/netlink"
	"fmt"
)

type NetnsAwaredResource interface {
	pkgnetns.NetNsAwareResource
	GetInterfaceName() string
	GetType() string
}

func CheckExist(ctx context.Context, res NetnsAwaredResource) (bool, error) {
	var exist *bool = new(bool)
	*exist = false
	err := pkgnetns.WithNsHandleSafe(ctx, res, func(handle *netlink.Handle) error {
		lk, err := handle.LinkByName(res.GetInterfaceName())
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); ok {
				return nil
			}
			return fmt.Errorf("failed to get link %s of type %s: %w", res.GetInterfaceName(), res.GetType(), err)
		}

		*exist = lk != nil
		return nil
	})
	return *exist, err
}
