package stub

import (
	context "context"
	"fmt"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	netlink "github.com/vishvananda/netlink"
)

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

func ToStatusWrapper(ctx context.Context, res NetnsAwaredProbable) (*StatusWrapper, error) {
	name := res.GetInterfaceName()
	ty := res.GetType()
	exist, err := CheckExist(ctx, res)
	if err != nil {
		return nil, fmt.Errorf("failed to check if resource exists: %w", err)
	}
	if !exist {
		return &StatusWrapper{Name: name, Type: ty, Exists: false}, nil
	}
	status, err := res.ToStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get status of resource: %w", err)
	}
	return &StatusWrapper{Name: name, Type: ty, Exists: true, Status: status}, nil
}
