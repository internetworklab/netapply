package stub

import (
	"context"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
)

type NetnsAwaredResource interface {
	pkgnetns.NetNsAwareResource
	GetInterfaceName() string
	GetType() string
}

type InterfaceStatus interface {
	IsEqual(other InterfaceStatus) bool
}

type NetnsAwaredProbable interface {
	NetnsAwaredResource
	CheckExist(ctx context.Context) (bool, error)
	ToStatus(ctx context.Context) (InterfaceStatus, error)
}

type StatusWrapper struct {
	Name   string          `json:"name" bson:"name" yaml:"name"`
	Type   string          `json:"type" bson:"type" yaml:"type"`
	Exists bool            `json:"exists" bson:"exists" yaml:"exists"`
	Status InterfaceStatus `json:"status,omitempty" bson:"status,omitempty" yaml:"status,omitempty"`
}

type NetnsIdentifiableProvisioner interface {
	pkgreconcile.ResourceProvisioner
	pkgnetns.NetNsAwareResource
}

type StubProvisionersList interface {
	pkgnetns.MultiNetnsResource
	GetProvisioners() []NetnsIdentifiableProvisioner
	GetType() string
}

type StubInterfaceCanceller struct {
	InterfaceName string
	NetnsInfo     *pkgnetns.NetNsInfo
	Type          string
}

type StubResourceListChangeSet struct {
	addedResources   []NetnsIdentifiableProvisioner
	removedResources []pkgreconcile.ResourceCanceller
	updatedResources []pkgreconcile.InterfaceChangeSet
}
