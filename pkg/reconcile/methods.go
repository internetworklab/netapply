package reconcile

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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
				log.Printf("Removing interface %s in %s ...", canceller.GetInterfaceName(), pkgdocker.GetContainerDisplayName(canceller.GetContainerName()))
				if err := canceller.Cancel(ctx); err != nil {
					return fmt.Errorf("failed to cancel interface: %w", err)
				}
			}
		}

		for _, updatedInterface := range dpChangeSet.UpdatedResources {
			for _, changeSet := range updatedInterface {
				if changeSet.HasUpdates() {
					log.Printf("Updating interface %s in %s ...", changeSet.GetInterfaceName(), pkgdocker.GetContainerDisplayName(changeSet.GetContainerName()))
					if err := changeSet.Apply(ctx); err != nil {
						return fmt.Errorf("failed to update interface: %w", err)
					}
				}
			}
		}

		for _, provisioner := range reOrderAddedInterfaces(dpChangeSet.AddedResources) {
			log.Printf("Creating interface %s in %s ...", provisioner.GetInterfaceName(), pkgdocker.GetContainerDisplayName(provisioner.GetContainerName()))
			if err := provisioner.Create(ctx); err != nil {
				return fmt.Errorf("failed to create interface: %w", err)
			}
		}
	}
	return nil
}

func GetInterfaceFromContainer(ctx context.Context, containerName *string, linkType string) (map[string]ResourceCanceller, error) {
	type result struct {
		ifaces map[string]ResourceCanceller
	}

	res := new(result)
	res.ifaces = make(map[string]ResourceCanceller, 0)

	err := pkgdocker.WithNsHandleSafe(ctx, containerName, func(handle *netlink.Handle) error {
		links, err := handle.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list links: %w", err)
		}

		for _, link := range links {
			if strings.HasPrefix(link.Attrs().Name, "eth") {
				continue
			}

			if strings.HasPrefix(link.Attrs().Name, "lo") {
				continue
			}

			if link.Type() == linkType {
				res.ifaces[link.Attrs().Name] = &pkginterfacestub.StubInterfaceCanceller{ContainerName: containerName, InterfaceName: link.Attrs().Name}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get interface from container: %w", err)
	}

	return res.ifaces, nil
}

func IndexProvisionersList(ctx context.Context, provisionersList []ResourceProvisioner) (map[string]map[string]ResourceProvisioner, error) {
	specsMap := make(map[string]map[string]ResourceProvisioner)
	for _, provisioner := range provisionersList {
		nsKey := string(pkgdocker.GetContainerKey(provisioner.GetContainerName()))
		if _, ok := specsMap[nsKey]; !ok {
			specsMap[nsKey] = make(map[string]ResourceProvisioner)
		}
		specsMap[nsKey][provisioner.GetInterfaceName()] = provisioner
	}
	return specsMap, nil
}

func (dpChangeSet *ResourceListChangeSet) Log() {

	rows := make([]table.Row, 0)
	for _, ifaces := range dpChangeSet.AddedResources {
		for _, iface := range ifaces {
			rows = append(rows,
				table.Row{
					"Added",
					pkgdocker.GetContainerDisplayName(iface.GetContainerName()),
					iface.GetInterfaceName(),
					iface.GetType(),
				},
			)
		}
	}

	for _, ifaces := range dpChangeSet.RemovedResources {
		for _, iface := range ifaces {
			rows = append(rows,
				table.Row{
					"Removed",
					pkgdocker.GetContainerDisplayName(iface.GetContainerName()),
					iface.GetInterfaceName(),
					"-",
				},
			)
		}
	}

	for _, ifaces := range dpChangeSet.UpdatedResources {
		for _, iface := range ifaces {
			rows = append(rows,
				table.Row{
					"Updated",
					pkgdocker.GetContainerDisplayName(iface.GetContainerName()),
					iface.GetInterfaceName(),
					"-",
				},
			)
		}
	}

	// table with some amount of customization
	tw := table.NewWriter()
	// append a header row
	tw.AppendHeader(table.Row{"Direction", "Container", "Resource", "Type"})
	// append some data rows
	tw.AppendRows(rows)
	tw.SetStyle(table.StyleLight)
	// customize the style and change some stuff
	tw.Style().Format.Header = text.FormatLower
	tw.Style().Format.Row = text.FormatLower
	tw.Style().Format.Footer = text.FormatLower
	tw.Style().Options.SeparateColumns = false
	// render it
	fmt.Println(tw.Render())
}

func DetectChangesForProvisionersList(ctx context.Context, provisionersList ResourceProvisionersList) (*ResourceListChangeSet, error) {
	specsMap, err := IndexProvisionersList(ctx, provisionersList.GetProvisioners())
	if err != nil {
		return nil, fmt.Errorf("failed to index resources in spec: %w", err)
	}

	currentResourcesMap, err := provisionersList.IndexCurrentResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to index current resources: %w", err)
	}

	commonSet := make(map[string]map[string]ResourceProvisioner)

	changeSet := new(ResourceListChangeSet)
	for nsKey, subMap := range currentResourcesMap {
		for resKey, resCanceller := range subMap {
			if _, ok := specsMap[nsKey]; !ok {
				if _, hit := changeSet.RemovedResources[nsKey]; !hit {
					changeSet.RemovedResources[nsKey] = make([]ResourceCanceller, 0)
				}
				changeSet.RemovedResources[nsKey] = append(changeSet.RemovedResources[nsKey], resCanceller)
				continue
			}

			if _, ok := specsMap[nsKey][resKey]; !ok {
				if _, hit := changeSet.RemovedResources[nsKey]; !hit {
					changeSet.RemovedResources[nsKey] = make([]ResourceCanceller, 0)
				}
				changeSet.RemovedResources[nsKey] = append(changeSet.RemovedResources[nsKey], resCanceller)
				continue
			}

			// Now, since the resource is both set of specs and set of current resources, we add it into the set of common resources
			if _, ok := commonSet[nsKey]; !ok {
				commonSet[nsKey] = make(map[string]ResourceProvisioner)
			}
			commonSet[nsKey][resKey] = specsMap[nsKey][resKey]
		}
	}

	for nsKey, subMap := range specsMap {
		for resKey, resProvisioner := range subMap {
			if _, ok := currentResourcesMap[nsKey]; !ok {
				if _, hit := changeSet.AddedResources[nsKey]; !hit {
					changeSet.AddedResources[nsKey] = make([]ResourceProvisioner, 0)
				}
				changeSet.AddedResources[nsKey] = append(changeSet.AddedResources[nsKey], resProvisioner)
				continue
			}

			if _, ok := currentResourcesMap[nsKey][resKey]; !ok {
				if _, hit := changeSet.AddedResources[nsKey]; !hit {
					changeSet.AddedResources[nsKey] = make([]ResourceProvisioner, 0)
				}
				changeSet.AddedResources[nsKey] = append(changeSet.AddedResources[nsKey], resProvisioner)
				continue
			}

			// Now, since the resource is both set of specs and set of current resources, we add it into the set of common resources
			if _, ok := commonSet[nsKey]; !ok {
				commonSet[nsKey] = make(map[string]ResourceProvisioner)
			}
			commonSet[nsKey][resKey] = resProvisioner
		}
	}

	for nsKey, subMap := range commonSet {
		for resKey, resProvisioner := range subMap {
			exist, err := resProvisioner.CheckExist(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to check if resource exists, resource in common set but doesn't actually exists: %w", err)
			}
			if !exist {
				return nil, fmt.Errorf("failed to check if resource exists, resource in common set but doesn't actually exists")
			}

			changes, err := resProvisioner.DetectChanges(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to detect changes in resource %s in container %s: %w", resKey, nsKey, err)
			}

			if changes != nil && changes.HasUpdates() {
				if _, hit := changeSet.UpdatedResources[nsKey]; !hit {
					changeSet.UpdatedResources[nsKey] = make([]InterfaceChangeSet, 0)
				}
				changeSet.UpdatedResources[nsKey] = append(changeSet.UpdatedResources[nsKey], changes)
				continue
			}
		}
	}

	return changeSet, nil
}

func IndexStubNetlinkInterfaceList(ctx context.Context, interfaceList StubNetlinkInterfaceList) (map[string]map[string]ResourceCanceller, error) {
	currentResourcesMap := make(map[string]map[string]ResourceCanceller)
	for _, container := range interfaceList.GetContainers() {
		nsKey := string(pkgdocker.GetContainerKey(&container))
		ifaces, err := GetInterfaceFromContainer(ctx, &container, interfaceList.GetType())
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from container: %w", err)
		}
		if len(ifaces) > 0 {
			if _, ok := currentResourcesMap[nsKey]; !ok {
				currentResourcesMap[nsKey] = make(map[string]ResourceCanceller)
			}
			for _, ifaceCanceller := range ifaces {
				currentResourcesMap[nsKey][ifaceCanceller.GetInterfaceName()] = ifaceCanceller
			}
		}
	}

	return currentResourcesMap, nil
}

func CheckResourceExistInSpec(ctx context.Context, specsMap map[string]map[string]ResourceProvisioner, resource ResourceCanceller) (bool, error) {
	nsKey := string(pkgdocker.GetContainerKey(resource.GetContainerName()))
	if subSpecsMap, ok := specsMap[nsKey]; ok {
		if _, ok := subSpecsMap[resource.GetInterfaceName()]; ok {
			// Because, we assumed, that, if two resources are identical, they should generate the same resource name
			//  (hence the result of .GetInterfaceName() call should be equal)
			return true, nil
		}
	}

	return false, nil
}
