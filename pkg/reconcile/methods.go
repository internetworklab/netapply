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

	mergedAdded := make(map[string][]ResourceProvisioner)
	for k, v := range dpChangeSet.AddedResources {
		mergedAdded[k] = append(mergedAdded[k], v...)
	}
	for k, v := range other.AddedResources {
		if curr, ok := mergedAdded[k]; ok {
			mergedAdded[k] = append(curr, v...)
		} else {
			mergedAdded[k] = v
		}
	}

	mergedUpdated := make(map[string][]InterfaceChangeSet)
	for k, v := range dpChangeSet.UpdatedResources {
		mergedUpdated[k] = append(mergedUpdated[k], v...)
	}
	for k, v := range other.UpdatedResources {
		if curr, ok := mergedUpdated[k]; ok {
			mergedUpdated[k] = append(curr, v...)
		} else {
			mergedUpdated[k] = v
		}
	}

	mergedRemoved := make(map[string][]ResourceCanceller)
	for k, v := range dpChangeSet.RemovedResources {
		mergedRemoved[k] = append(mergedRemoved[k], v...)
	}
	for k, v := range other.RemovedResources {
		if curr, ok := mergedRemoved[k]; ok {
			mergedRemoved[k] = append(curr, v...)
		} else {
			mergedRemoved[k] = v
		}
	}

	result.AddedResources = mergedAdded
	result.UpdatedResources = mergedUpdated
	result.RemovedResources = mergedRemoved

	return result
}

func (dpChangeSet *ResourceListChangeSet) HasChanges() bool {
	if dpChangeSet != nil {
		for _, addedInterface := range dpChangeSet.AddedResources {
			if len(addedInterface) > 0 {
				return true
			}
		}
		for _, updatedInterface := range dpChangeSet.UpdatedResources {
			if len(updatedInterface) > 0 {
				return true
			}
		}
		for _, removedInterface := range dpChangeSet.RemovedResources {
			if len(removedInterface) > 0 {
				return true
			}
		}
	}

	return false
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

func reOrderAddedInterfaces(provisioners map[string][]ResourceProvisioner) []ResourceProvisioner {
	results := make([]ResourceProvisioner, 0)
	for _, provisioner := range provisioners {
		results = append(results, provisioner...)
	}

	sort.Slice(results, func(i, j int) bool {
		return getOrderByType(results[i].GetType()) < getOrderByType(results[j].GetType())
	})

	return results
}

func (dpChangeSet *ResourceListChangeSet) Apply(ctx context.Context) error {
	if dpChangeSet.HasChanges() {
		for _, removedInterface := range dpChangeSet.RemovedResources {
			for _, canceller := range removedInterface {
				if err := canceller.Cancel(ctx); err != nil {
					return fmt.Errorf("failed to cancel interface: %w", err)
				}
			}
		}

		for _, updatedInterface := range dpChangeSet.UpdatedResources {
			for _, changeSet := range updatedInterface {
				if changeSet.HasUpdates() {
					if err := changeSet.Apply(ctx); err != nil {
						return fmt.Errorf("failed to update interface: %w", err)
					}
				}
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

// func (dpChangeSet *ResourceListChangeSet) Log() {
// 	if dpChangeSet == nil {
// 		return
// 	}

// 	rows := make([]table.Row, 0)
// 	for _, ifaces := range dpChangeSet.AddedResources {
// 		for _, iface := range ifaces {
// 			rows = append(rows,
// 				table.Row{
// 					"Added",
// 					pkgutils.GetContainerDisplayName(iface.GetContainerName()),
// 					iface.GetInterfaceName(),
// 					iface.GetType(),
// 				},
// 			)
// 		}
// 	}

// 	for _, ifaces := range dpChangeSet.RemovedResources {
// 		for _, iface := range ifaces {
// 			rows = append(rows,
// 				table.Row{
// 					"Removed",
// 					pkgutils.GetContainerDisplayName(iface.GetContainerName()),
// 					iface.GetInterfaceName(),
// 					iface.GetType(),
// 				},
// 			)
// 		}
// 	}

// 	for _, ifaces := range dpChangeSet.UpdatedResources {
// 		for _, iface := range ifaces {
// 			rows = append(rows,
// 				table.Row{
// 					"Updated",
// 					pkgutils.GetContainerDisplayName(iface.GetContainerName()),
// 					iface.GetInterfaceName(),
// 					iface.GetType(),
// 				},
// 			)
// 		}
// 	}

// 	// table with some amount of customization
// 	tw := table.NewWriter()
// 	// append a header row
// 	tw.AppendHeader(table.Row{"Direction", "Container", "Resource", "Type"})
// 	// append some data rows
// 	tw.AppendRows(rows)
// 	tw.SetStyle(table.StyleLight)
// 	// customize the style and change some stuff
// 	tw.Style().Format.Header = text.FormatLower
// 	tw.Style().Format.Row = text.FormatLower
// 	tw.Style().Format.Footer = text.FormatLower
// 	tw.Style().Options.SeparateColumns = false
// 	// render it
// 	fmt.Println(tw.Render())
// }
