package reconcile

import (
	"context"
)

type InterfaceChangeSet interface {
	Apply(ctx context.Context) error
	HasUpdates() bool
	GetInterfaceName() string
	GetContainerName() *string
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

	// Get the container name for indexing and logging purposes.
	GetContainerName() *string

	// Check if the interface is exist
	// If it's not exist, should return (false, nil), error is non-nil only when there is error (and resource-doesnt exist is not an error)
	CheckExist(ctx context.Context) (bool, error)

	// Get type of the interface(resource), so that it can be compared for priority of creation
	GetType() string
}

type ResourceProvisionersList interface {
	GetType() string
	GetProvisioners() []ResourceProvisioner
	IndexCurrentResources(ctx context.Context) (map[string]map[string]ResourceCanceller, error)
	CheckResourceExistInSpec(ctx context.Context, specsMap map[string]map[string]ResourceProvisioner, resource ResourceCanceller) (bool, error)

	// If delete is true, meaning that should ignore those presented in actual state but not in the spec,
	// its just like the `--delete` flag of the `rsync` command.
	DetectChanges(ctx context.Context, delete bool) (*ResourceListChangeSet, error)
}

type ResourceCanceller interface {
	Cancel(ctx context.Context) error
	GetInterfaceName() string
	GetContainerName() *string
	GetType() string
}

type ResourceListChangeSet struct {
	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be added
	AddedResources map[string][]ResourceProvisioner

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be updated
	UpdatedResources map[string][]InterfaceChangeSet

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be removed
	RemovedResources map[string][]ResourceCanceller
}

// netns -> iface name -> iface canceller
type CurrentIfaceIndex = map[string]map[string]ResourceCanceller

type SpecIfaceIndex = map[string]map[string]ResourceProvisioner

type StubNetlinkInterfaceList interface {
	GetType() string
	GetContainers() []string
}
