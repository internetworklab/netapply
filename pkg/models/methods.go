package models

import (
	"context"
	"fmt"
	"log"

	"github.com/vishvananda/netlink"

	"sort"

	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
)

func (nodeConfig *NodeConfig) Up(ctx context.Context, delete bool) error {
	if nodeConfig.Resources != nil {
		log.Println("Setting up dataplane ...")
		if err := nodeConfig.Resources.Reconcile(ctx, delete); err != nil {
			return fmt.Errorf("failed to reconcile dataplane: %w", err)
		}
	}
	return nil
}

func appendNoNil(targets []pkgreconcile.ResourceProvisionersList, target pkgreconcile.ResourceProvisionersList) []pkgreconcile.ResourceProvisionersList {
	if target == nil {
		return targets
	}
	return append(targets, target)
}

func reOrderAddedInterfaces(provisioners map[string]pkgreconcile.ResourceProvisioner) []pkgreconcile.ResourceProvisioner {
	results := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, provisioner := range provisioners {
		results = append(results, provisioner)
	}

	sort.Slice(results, func(i, j int) bool {
		return getOrderByType(results[i].GetType()) < getOrderByType(results[j].GetType())
	})

	return results
}

func getOrderByType(ty string) int16 {
	// the lower is the number, the higher is the priority
	orderMap := make(map[string]int16)
	// We use tuntap type for openvpn container-based interface, so it have to be created earlier,
	// since other interfaces might depend on it.
	orderMap[new(netlink.Tuntap).Type()] = 0
	orderMap[new(netlink.Vrf).Type()] = 1
	orderMap[new(netlink.Dummy).Type()] = 2
	orderMap[new(netlink.Veth).Type()] = 3
	orderMap[new(netlink.Wireguard).Type()] = 4

	// VxLAN might relys on other interface as underlay, so it should be created later than that.
	// For example, VxLAN over WireGuard.
	orderMap[new(netlink.Vxlan).Type()] = 5
	orderMap["route"] = 254
	orderMap[new(netlink.Bridge).Type()] = 255
	const defaultOrder int16 = 128

	if order, ok := orderMap[ty]; ok {
		return order
	}

	// todo: maybe complete more types here

	return defaultOrder
}

type WrappedResourceListChangeSet struct {
	original         pkgreconcile.ResourceListChangeSet
	addedResources   map[string]pkgreconcile.ResourceProvisioner
	removedResources map[string]pkgreconcile.ResourceCanceller
	updatedResources map[string]pkgreconcile.InterfaceChangeSet
}

func (wrapped *WrappedResourceListChangeSet) GetAddedResources() map[string]pkgreconcile.ResourceProvisioner {
	return wrapped.original.GetAddedResources()
}

func (wrapped *WrappedResourceListChangeSet) GetUpdatedResources() map[string]pkgreconcile.InterfaceChangeSet {
	return wrapped.original.GetUpdatedResources()
}

func (wrapped *WrappedResourceListChangeSet) GetRemovedResources() map[string]pkgreconcile.ResourceCanceller {
	return wrapped.original.GetRemovedResources()
}

func (changeset *WrappedResourceListChangeSet) Merge(other pkgreconcile.ResourceListChangeSet) (*WrappedResourceListChangeSet, error) {
	if changeset == nil {
		panic("wrappedresourcelistchangeset must be initialized before use")
	}

	mergedAddedSet := make(map[string]pkgreconcile.ResourceProvisioner)
	mergedRemovedSet := make(map[string]pkgreconcile.ResourceCanceller)
	mergedUpdatedSet := make(map[string]pkgreconcile.InterfaceChangeSet)
	for k, v := range changeset.addedResources {
		mergedAddedSet[k] = v
	}
	for k, v := range changeset.removedResources {
		mergedRemovedSet[k] = v
	}
	for k, v := range changeset.updatedResources {
		mergedUpdatedSet[k] = v
	}

	for k, v := range other.GetAddedResources() {
		if curr, ok := mergedAddedSet[k]; ok {
			if curr.GetType() == v.GetType() {
				return nil, fmt.Errorf("duplicate added resource in changeset: %s", k)
			}

			lhs := mergedAddedSet[k]
			delete(mergedAddedSet, k)
			mergedAddedSet[lhs.GetType()+":"+k] = lhs
			mergedAddedSet[v.GetType()+":"+k] = v
		} else {
			mergedAddedSet[k] = v
		}
	}

	for k, v := range other.GetRemovedResources() {
		if curr, ok := mergedRemovedSet[k]; ok {
			if curr.GetType() == v.GetType() {
				return nil, fmt.Errorf("duplicate removed resource in changeset: %s", k)
			}
			lhs := mergedRemovedSet[k]
			delete(mergedRemovedSet, k)
			mergedRemovedSet[lhs.GetType()+":"+k] = lhs
			mergedRemovedSet[v.GetType()+":"+k] = v
		} else {
			mergedRemovedSet[k] = v
		}
	}

	for k, v := range other.GetUpdatedResources() {
		if curr, ok := mergedUpdatedSet[k]; ok {
			if curr.GetType() == v.GetType() {
				return nil, fmt.Errorf("duplicate updated resource in changeset: %s", k)
			}
			lhs := mergedUpdatedSet[k]
			delete(mergedUpdatedSet, k)
			mergedUpdatedSet[lhs.GetType()+":"+k] = lhs
			mergedUpdatedSet[v.GetType()+":"+k] = v
		} else {
			mergedUpdatedSet[k] = v
		}
	}

	mergedChangeSet := new(WrappedResourceListChangeSet)
	mergedChangeSet.addedResources = mergedAddedSet
	mergedChangeSet.removedResources = mergedRemovedSet
	mergedChangeSet.updatedResources = mergedUpdatedSet
	return mergedChangeSet, nil

}

func (changeset *WrappedResourceListChangeSet) HasUpdates() bool {
	if changeset == nil {
		return false
	}

	return len(changeset.addedResources) > 0 || len(changeset.removedResources) > 0 || len(changeset.updatedResources) > 0
}

func (dpConfig *ResourcesConfig) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {

	reconcileTargets := make([]pkgreconcile.ResourceProvisionersList, 0)
	reconcileTargets = appendNoNil(reconcileTargets, dpConfig.BirdBGP)

	mergedChangeSet := new(WrappedResourceListChangeSet)

	for _, reconcileTarget := range reconcileTargets {
		log.Println("Detecting changes for", reconcileTarget.GetType(), "...")
		subChangeSet, err := reconcileTarget.DetectChanges(ctx, delete)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes for %s: %w", reconcileTarget.GetType(), err)
		}
		if subChangeSet != nil && subChangeSet.HasUpdates() {
			log.Println("Found changes for", reconcileTarget.GetType())
			mergedChangeSet, err = mergedChangeSet.Merge(subChangeSet)
			if err != nil {
				return nil, fmt.Errorf("failed to merge changes: %w", err)
			}
		}
	}

	return mergedChangeSet, nil
}

func ApplyChanges(ctx context.Context, changeset pkgreconcile.ResourceListChangeSet) error {
	for _, canceller := range changeset.GetRemovedResources() {
		if err := canceller.Cancel(ctx); err != nil {
			return fmt.Errorf("failed to cancel resource: %w", err)
		}
	}

	for _, changeSet := range changeset.GetUpdatedResources() {
		if err := changeSet.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}
	}

	for _, provisioner := range reOrderAddedInterfaces(changeset.GetAddedResources()) {
		if err := provisioner.Create(ctx); err != nil {
			return fmt.Errorf("failed to create resource: %w", err)
		}
	}

	return nil
}

func (dpConfig *ResourcesConfig) Reconcile(ctx context.Context, delete bool) error {
	log.Println("Detecting changes for dataplane config ...")
	changeSet, err := dpConfig.DetectChanges(ctx, delete)
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}

	maxLoop := 10
	iterId := 0

	for changeSet != nil && changeSet.HasUpdates() && maxLoop > 0 {

		log.Println("Applying changes for dataplane config ...")
		if err := ApplyChanges(ctx, changeSet); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}

		log.Println("Changeset is applied to dataplane config, detecting changes again ...")
		changeSet, err = dpConfig.DetectChanges(ctx, delete)
		if err != nil {
			return fmt.Errorf("failed to detect changes: %w", err)
		}
		maxLoop--
		iterId++
	}

	if maxLoop == 0 && changeSet != nil && changeSet.HasUpdates() {
		return fmt.Errorf("failed to reconcile dataplane config, max loop reached")
	}

	return nil
}
