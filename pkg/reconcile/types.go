package reconcile

import (
	"context"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
)

type InterfaceChangeSet interface {
	Apply(ctx context.Context) error
	HasUpdates() bool
	GetInterfaceName() string
	GetNetnsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error)
	GetType() string
}

type ResourceProvisioner interface {
	// In case the interface is not created yet, one can call `Create` to create the interface.
	Create(ctx context.Context) error

	// In case the interface is already created, one can call `DetectChanges` to detect any changes.
	// Also, a `*InterfaceChangeSet` might be nil regardless of there is error or not.
	DetectChanges(ctx context.Context) (InterfaceChangeSet, error)

	// Get the interface name (or resource name) for indexing and logging purposes.
	GetInterfaceName() string

	// Check if the interface is actually exist in the system,
	// If it's not exist, should return (false, nil), error is non-nil only when there is error (and resource-doesnt exist is not considered as an error)
	CheckExist(ctx context.Context) (bool, error)

	// Get type of the interface(resource), so that it can be compared for priority of creation
	GetType() string

	// Check if the resource has been marked as soft-deleted, mainly called by the upper layer's GetProvisioners function.
	IsSoftDeleted() bool

	// when in host netns, return nil as *NetNsInfo
	GetPrimaryNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error)
}

type ResourceProvisionersList interface {
	GetType() string

	// If delete is true, meaning that should ignore those presented in actual state but not in the spec,
	// its just like the `--delete` flag of the `rsync` command.
	DetectChanges(ctx context.Context, delete bool) (*ResourceListChangeSet, error)
}

type ResourceCanceller interface {
	Cancel(ctx context.Context) error
	GetInterfaceName() string
	GetType() string
	GetNetnsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error)
}

type ResourceListChangeSet struct {
	// key is the identifier of the netns (e.g., pid)
	AddedResources   map[string][]ResourceProvisioner
	UpdatedResources map[string][]InterfaceChangeSet
	RemovedResources map[string][]ResourceCanceller
}
