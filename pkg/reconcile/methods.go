package reconcile

import (
	"context"
	"fmt"
	"sort"

	"github.com/vishvananda/netlink"
)

func (dpChangeSet *ResourceListChangeSet) Merge(other *ResourceListChangeSet) *ResourceListChangeSet {
	if dpChangeSet == nil {
		return other
	}

	if other == nil {
		return dpChangeSet
	}

	result := new(ResourceListChangeSet)

	mergedAdded := make(map[string]ResourceProvisioner)
	mergedUpdated := make(map[string]InterfaceChangeSet)
	mergedRemoved := make(map[string]ResourceCanceller)

	for k, v := range dpChangeSet.AddedResources {
		mergedAdded[k+":"+v.GetType()] = v
	}
	for k, v := range other.AddedResources {
		mergedAdded[k+":"+v.GetType()] = v
	}

	for k, v := range dpChangeSet.UpdatedResources {
		mergedUpdated[k+":"+v.GetType()] = v
	}
	for k, v := range other.UpdatedResources {
		mergedUpdated[k+":"+v.GetType()] = v
	}

	for k, v := range dpChangeSet.RemovedResources {
		mergedRemoved[k+":"+v.GetType()] = v
	}
	for k, v := range other.RemovedResources {
		mergedRemoved[k+":"+v.GetType()] = v
	}

	result.AddedResources = mergedAdded
	result.UpdatedResources = mergedUpdated
	result.RemovedResources = mergedRemoved
	return result
}

func (dpChangeSet *ResourceListChangeSet) HasChanges() bool {
	if dpChangeSet == nil {
		return false
	}
	return len(dpChangeSet.RemovedResources)+len(dpChangeSet.UpdatedResources)+len(dpChangeSet.AddedResources) > 0
}

func reOrderAddedInterfaces(provisioners map[string]ResourceProvisioner) []ResourceProvisioner {
	results := make([]ResourceProvisioner, 0)
	for _, provisioner := range provisioners {
		results = append(results, provisioner)
	}

	sort.Slice(results, func(i, j int) bool {
		return getOrderByType(results[i].GetType()) < getOrderByType(results[j].GetType())
	})

	return results
}

func (dpChangeSet *ResourceListChangeSet) Apply(ctx context.Context) error {
	if dpChangeSet.HasChanges() {
		for _, canceller := range dpChangeSet.RemovedResources {
			if err := canceller.Cancel(ctx); err != nil {
				return fmt.Errorf("failed to cancel interface: %w", err)
			}
		}

		for _, changeSet := range dpChangeSet.UpdatedResources {
			if err := changeSet.Apply(ctx); err != nil {
				return fmt.Errorf("failed to update interface: %w", err)
			}
		}

		for _, provisioner := range reOrderAddedInterfaces(dpChangeSet.AddedResources) {
			if err := provisioner.Create(ctx); err != nil {
				return fmt.Errorf("failed to create interface: %w", err)
			}
		}
	}
	return nil
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
