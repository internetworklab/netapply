package stub

import (
	"context"
	"fmt"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	netlink "github.com/vishvananda/netlink"
)


func (canceller *StubInterfaceCanceller) GetInterfaceName() string {
	return canceller.InterfaceName
}

func (canceller *StubInterfaceCanceller) GetType() string {
	return canceller.Type
}

func (canceller *StubInterfaceCanceller) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return canceller.NetnsInfo, nil
}

func (canceller *StubInterfaceCanceller) Cancel(ctx context.Context) error {
	return pkgnetns.WithNsHandleSafe(ctx, canceller, func(h *netlink.Handle) error {
		link, err := h.LinkByName(canceller.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get link by name to delete: %w", err)
		}
		if err := h.LinkDel(link); err != nil {
			return fmt.Errorf("failed to delete link: %w", err)
		}
		return nil
	})
}


func (changeSet *StubResourceListChangeSet) GetAddedResources() []pkgreconcile.ResourceProvisioner {
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, provisioner := range changeSet.addedResources {
		provisioners = append(provisioners, provisioner)
	}
	return provisioners
}

func (changeSet *StubResourceListChangeSet) GetRemovedResources() []pkgreconcile.ResourceCanceller {
	return changeSet.removedResources
}

func (changeSet *StubResourceListChangeSet) GetUpdatedResources() []pkgreconcile.InterfaceChangeSet {
	return changeSet.updatedResources
}

func (changeSet *StubResourceListChangeSet) HasUpdates() bool {
	if changeSet == nil {
		return false
	}

	return len(changeSet.addedResources) > 0 || len(changeSet.removedResources) > 0 || len(changeSet.updatedResources) > 0
}

func DetectChanges(ctx context.Context, stubProvisionersList StubProvisionersList, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	changeSet := new(StubResourceListChangeSet)
	changeSet.addedResources = make([]NetnsIdentifiableProvisioner, 0)
	changeSet.removedResources = make([]pkgreconcile.ResourceCanceller, 0)
	changeSet.updatedResources = make([]pkgreconcile.InterfaceChangeSet, 0)

	// indexing specs, with netns key as the key
	specIndex := make(map[string]map[string]NetnsIdentifiableProvisioner)
	for _, wgCfg := range stubProvisionersList.GetProvisioners() {
		nsInfo, err := wgCfg.GetNetNsInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get netns info: %w", err)
		}
		netnsKey, err := nsInfo.ToNetnsKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get netns key: %w", err)
		}
		if _, ok := specIndex[netnsKey]; !ok {
			specIndex[netnsKey] = make(map[string]NetnsIdentifiableProvisioner)
		}
		specIndex[netnsKey][wgCfg.GetInterfaceName()] = wgCfg
	}

	var closureWrapper struct {
		commonSet map[string]map[string]NetnsIdentifiableProvisioner
	}
	closureWrapperPtr := &closureWrapper
	closureWrapperPtr.commonSet = make(map[string]map[string]NetnsIdentifiableProvisioner)
	for netnsKey := range specIndex {
		closureWrapperPtr.commonSet[netnsKey] = make(map[string]NetnsIdentifiableProvisioner)
	}

	ty := new(netlink.Wireguard).Type()
	err := pkgnetns.WithMultiNetnsHandle(ctx, stubProvisionersList, func(h *netlink.Handle, netnsInfo *pkgnetns.NetNsInfo) error {
		netnsKey, err := netnsInfo.ToNetnsKey()
		if err != nil {
			return fmt.Errorf("failed to get netns key: %w", err)
		}

		superfluous := make([]pkgreconcile.ResourceCanceller, 0)

		links, err := h.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list links: %w", err)
		}

		for _, lk := range links {
			if lk.Type() != ty {
				continue
			}

			if m, ok := specIndex[netnsKey]; ok {
				if x, ok := m[lk.Attrs().Name]; ok {
					closureWrapperPtr.commonSet[netnsKey][lk.Attrs().Name] = x
					continue
				}
			}

			if delete {
				superfluous = append(superfluous, &StubInterfaceCanceller{NetnsInfo: netnsInfo, InterfaceName: lk.Attrs().Name, Type: stubProvisionersList.GetType()})
			}
		}

		if superfluous != nil {
			changeSet.removedResources = append(changeSet.removedResources, superfluous...)
		}

		return nil
	})

	for netnsKey, specs := range specIndex {
		for interfaceName, spec := range specs {
			if _, ok := closureWrapperPtr.commonSet[netnsKey][interfaceName]; !ok {
				changeSet.addedResources = append(changeSet.addedResources, spec)
				continue
			}
		}
	}

	for netnsKey := range closureWrapperPtr.commonSet {
		for interfaceName, provisioner := range closureWrapperPtr.commonSet[netnsKey] {
			updates, err := provisioner.DetectChanges(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to detect changes for wireguard interface %s: %w", interfaceName, err)
			}
			if updates != nil && updates.HasUpdates() {
				changeSet.updatedResources = append(changeSet.updatedResources, updates)
				continue
			}
		}
	}

	return changeSet, err
}
