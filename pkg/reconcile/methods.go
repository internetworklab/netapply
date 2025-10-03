package reconcile

import (
	"context"
	"fmt"
	"log"
	"strings"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	"github.com/vishvananda/netlink"
)

func (dpChangeSet *DataplaneChangeSet) Merge(other *DataplaneChangeSet) *DataplaneChangeSet {
	if dpChangeSet == nil {
		return other
	}

	if other == nil {
		return dpChangeSet
	}

	result := new(DataplaneChangeSet)

	mergedAdded := make(map[string][]InterfaceProvisioner)
	for k, v := range dpChangeSet.AddedInterfaces {
		mergedAdded[k] = append(mergedAdded[k], v...)
	}
	for k, v := range other.AddedInterfaces {
		if curr, ok := mergedAdded[k]; ok {
			mergedAdded[k] = append(curr, v...)
		} else {
			mergedAdded[k] = v
		}
	}

	mergedUpdated := make(map[string][]InterfaceChangeSet)
	for k, v := range dpChangeSet.UpdatedInterfaces {
		mergedUpdated[k] = append(mergedUpdated[k], v...)
	}
	for k, v := range other.UpdatedInterfaces {
		if curr, ok := mergedUpdated[k]; ok {
			mergedUpdated[k] = append(curr, v...)
		} else {
			mergedUpdated[k] = v
		}
	}

	mergedRemoved := make(map[string][]InterfaceCanceller)
	for k, v := range dpChangeSet.RemovedInterfaces {
		mergedRemoved[k] = append(mergedRemoved[k], v...)
	}
	for k, v := range other.RemovedInterfaces {
		if curr, ok := mergedRemoved[k]; ok {
			mergedRemoved[k] = append(curr, v...)
		} else {
			mergedRemoved[k] = v
		}
	}

	result.AddedInterfaces = mergedAdded
	result.UpdatedInterfaces = mergedUpdated
	result.RemovedInterfaces = mergedRemoved

	return result
}

func (dpChangeSet *DataplaneChangeSet) HasChanges() bool {
	if dpChangeSet != nil {
		for _, addedInterface := range dpChangeSet.AddedInterfaces {
			if len(addedInterface) > 0 {
				return true
			}
		}
		for _, updatedInterface := range dpChangeSet.UpdatedInterfaces {
			if len(updatedInterface) > 0 {
				return true
			}
		}
		for _, removedInterface := range dpChangeSet.RemovedInterfaces {
			if len(removedInterface) > 0 {
				return true
			}
		}
	}

	return false
}

func (dpChangeSet *DataplaneChangeSet) Apply(ctx context.Context) error {
	if dpChangeSet.HasChanges() {
		for _, removedInterface := range dpChangeSet.RemovedInterfaces {
			for _, canceller := range removedInterface {
				log.Printf("Removing interface %s in %s ...", canceller.GetInterfaceName(), pkgdocker.GetContainerDisplayName(canceller.GetContainerName()))
				if err := canceller.Cancel(ctx); err != nil {
					return fmt.Errorf("failed to cancel interface: %w", err)
				}
			}
		}

		for _, updatedInterface := range dpChangeSet.UpdatedInterfaces {
			for _, changeSet := range updatedInterface {
				if changeSet.HasUpdates() {
					log.Printf("Updating interface %s in %s ...", changeSet.GetInterfaceName(), pkgdocker.GetContainerDisplayName(changeSet.GetContainerName()))
					if err := changeSet.Apply(ctx); err != nil {
						return fmt.Errorf("failed to update interface: %w", err)
					}
				}
			}
		}

		for _, addedInterface := range dpChangeSet.AddedInterfaces {
			for _, provisioner := range addedInterface {
				log.Printf("Creating interface %s in %s ...", provisioner.GetInterfaceName(), pkgdocker.GetContainerDisplayName(provisioner.GetContainerName()))
				if err := provisioner.Create(ctx); err != nil {
					return fmt.Errorf("failed to create interface: %w", err)
				}
			}
		}
	}
	return nil
}

func GetInterfaceFromContainer(ctx context.Context, containerName *string, linkType string) (map[string]InterfaceCanceller, error) {
	type result struct {
		ifaces map[string]InterfaceCanceller
	}

	res := new(result)
	res.ifaces = make(map[string]InterfaceCanceller, 0)

	err := pkgdocker.WithNsHandle(ctx, containerName, func(handle *netlink.Handle) error {
		links, err := handle.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list links: %w", err)
		}

		for _, link := range links {
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

func IndexCurrentIfaces(ctx context.Context, containers []string, netlinkIfType string, includeHostNetns bool) (CurrentIfaceIndex, error) {
	currentInterfaceListMap := make(map[string]map[string]InterfaceCanceller)
	for _, name := range containers {
		ifaces, err := GetInterfaceFromContainer(ctx, &name, netlinkIfType)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from container: %w", err)
		}
		currentInterfaceListMap[name] = ifaces
	}

	if includeHostNetns {
		hostInterfaceList, err := GetInterfaceFromContainer(ctx, nil, netlinkIfType)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from host: %w", err)
		}
		currentInterfaceListMap[string(pkgdocker.ContainerKeyHost)] = hostInterfaceList
	}

	return currentInterfaceListMap, nil
}

func IndexSpecIfaces(provisionerList []InterfaceProvisioner) (SpecIfaceIndex, error) {
	specInterfaceListMap := make(map[string]map[string]InterfaceProvisioner)
	for _, c := range provisionerList {
		contName := string(pkgdocker.GetContainerKey(c.GetContainerName()))

		if _, ok := specInterfaceListMap[contName]; !ok {
			specInterfaceListMap[contName] = make(map[string]InterfaceProvisioner, 0)
		}
		specInterfaceListMap[contName][c.GetInterfaceName()] = c
	}

	return specInterfaceListMap, nil
}

func DetectChangesInContainer(
	ctx context.Context,
	provisionerList map[string]InterfaceProvisioner,
	currentInterfacesInContainer map[string]InterfaceCanceller,
	container string,
) (*DataplaneChangeSet, error) {

	addedSet := make(map[string]InterfaceProvisioner)
	removedSet := make(map[string]InterfaceCanceller)
	commonSet := make(map[string]InterfaceProvisioner)
	updatedSet := make(map[string]InterfaceChangeSet)

	for _, provisioner := range provisionerList {
		if _, ok := currentInterfacesInContainer[provisioner.GetInterfaceName()]; !ok {
			addedSet[provisioner.GetInterfaceName()] = provisioner
		}
	}

	for _, currentInterface := range currentInterfacesInContainer {
		if p, ok := provisionerList[currentInterface.GetInterfaceName()]; ok {
			commonSet[currentInterface.GetInterfaceName()] = p
		} else {
			removedSet[currentInterface.GetInterfaceName()] = currentInterface
		}
	}

	for ifaceName, provisioner := range commonSet {
		changes, err := provisioner.DetectChanges(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes in container %s for interface %s: %w", container, ifaceName, err)
		}
		if changes != nil && changes.HasUpdates() {
			log.Printf("Found updates for interface %s in container %s: %v", ifaceName, container, changes.GetChangedItems())
			updatedSet[ifaceName] = changes
		}
	}

	addedList := make([]InterfaceProvisioner, 0)
	removedList := make([]InterfaceCanceller, 0)
	updatedList := make([]InterfaceChangeSet, 0)

	for _, provisioner := range addedSet {
		addedList = append(addedList, provisioner)
	}
	for _, currentInterface := range removedSet {
		removedList = append(removedList, currentInterface)
	}
	for _, changeset := range updatedSet {
		updatedList = append(updatedList, changeset)
	}

	changeSet := new(DataplaneChangeSet)
	changeSet.AddedInterfaces = make(map[string][]InterfaceProvisioner)
	changeSet.AddedInterfaces[container] = addedList

	changeSet.RemovedInterfaces = make(map[string][]InterfaceCanceller)
	changeSet.RemovedInterfaces[container] = removedList

	changeSet.UpdatedInterfaces = make(map[string][]InterfaceChangeSet)
	changeSet.UpdatedInterfaces[container] = updatedList

	return changeSet, nil
}

func DetectChangesFromProvisionerList(ctx context.Context, provisionerList []InterfaceProvisioner, netlinkIfType string, containers []string) (*DataplaneChangeSet, error) {

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces present in the container
	// for now, skip the host netns, so includeHostNetns is set to false
	currentInterfaceListMap, err := IndexCurrentIfaces(ctx, containers, netlinkIfType, false)
	if err != nil {
		return nil, fmt.Errorf("failed to index current interface: %w", err)
	}

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces present in the spec
	specInterfaceListMap, err := IndexSpecIfaces(provisionerList)
	if err != nil {
		return nil, fmt.Errorf("failed to index spec interface: %w", err)
	}

	combinedNsMap := make(map[string]interface{})
	for k := range currentInterfaceListMap {
		combinedNsMap[k] = true
	}
	for k := range specInterfaceListMap {
		combinedNsMap[k] = true
	}

	var totalChanges *DataplaneChangeSet

	for nsKey := range combinedNsMap {
		var provisionersInContainer map[string]InterfaceProvisioner
		if v, ok := specInterfaceListMap[nsKey]; ok {
			provisionersInContainer = v
		}

		var currentInterfacesInContainer map[string]InterfaceCanceller
		if v, ok := currentInterfaceListMap[nsKey]; ok {
			currentInterfacesInContainer = v
		}

		changes, err := DetectChangesInContainer(ctx, provisionersInContainer, currentInterfacesInContainer, nsKey)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes in container %s: %w", nsKey, err)
		}

		totalChanges = totalChanges.Merge(changes)
	}

	return totalChanges, nil
}

func (dpChangeSet *DataplaneChangeSet) Log() {
	log.Print("Dataplane change set:\n")

	log.Print("Removed interfaces:\n")
	for ns, ifaces := range dpChangeSet.RemovedInterfaces {
		ifaceList := make([]string, 0)
		for _, iface := range ifaces {
			ifaceList = append(ifaceList, iface.GetInterfaceName())
		}
		log.Printf("%v: %v", ns, strings.Join(ifaceList, ", "))
	}

	log.Print("Added interfaces:\n")
	for ns, ifaces := range dpChangeSet.AddedInterfaces {
		ifaceList := make([]string, 0)
		for _, iface := range ifaces {
			ifaceList = append(ifaceList, iface.GetInterfaceName())
		}
		log.Printf("%v: %v", ns, strings.Join(ifaceList, ", "))
	}

	log.Print("Updated interfaces:\n")
	for ns, ifaces := range dpChangeSet.UpdatedInterfaces {
		ifaceList := make([]string, 0)
		for _, iface := range ifaces {
			ifaceList = append(ifaceList, iface.GetInterfaceName())
		}
		log.Printf("%v: %v", ns, strings.Join(ifaceList, ", "))
	}

}
