package reconcile

import (
	"context"
)

type InterfaceChangeSet interface {
	Apply(ctx context.Context) error
	HasUpdates() bool
	GetInterfaceName() string
	GetContainerName() *string
	GetChangedItems() map[string]bool
}

type InterfaceProvisioner interface {
	// In case the interface is not created yet, one can call `Create` to create the interface.
	Create(ctx context.Context) error

	// In case the interface is already created, one can call `DetectChanges` to detect any changes.
	// Also, a `*InterfaceChangeSet` might be nil regardless of there is error or not.
	DetectChanges(ctx context.Context) (InterfaceChangeSet, error)

	// Get the interface name for indexing and logging purposes.
	GetInterfaceName() string

	// Get the container name for indexing and logging purposes.
	GetContainerName() *string
}

type InterfaceCanceller interface {
	Cancel(ctx context.Context) error
	GetInterfaceName() string
	GetContainerName() *string
}

type DataplaneChangeSet struct {
	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be added
	AddedInterfaces map[string][]InterfaceProvisioner

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be updated
	UpdatedInterfaces map[string][]InterfaceChangeSet

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be removed
	RemovedInterfaces map[string][]InterfaceCanceller
}

// netns -> iface name -> iface canceller
type CurrentIfaceIndex = map[string]map[string]InterfaceCanceller

type SpecIfaceIndex = map[string]map[string]InterfaceProvisioner
