package wireguard

import (
	"context"

	"fmt"

	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

// A WireGuardResourceListChangeSet is an implementation of ResourceListChangeSet interface.
type WireGuardResourceListChangeSet struct {
	addedResources   []pkgreconcile.ResourceProvisioner
	removedResources []pkgreconcile.ResourceCanceller
	updatedResources []pkgreconcile.InterfaceChangeSet
}

type WireGuardInterfaceCanceller struct {
	NetnsInfo     *pkgnetns.NetNsInfo
	InterfaceName string
}

func (wgInterfaceCanceller *WireGuardInterfaceCanceller) GetInterfaceName() string {
	return wgInterfaceCanceller.InterfaceName
}

func (wgInterfaceCanceller *WireGuardInterfaceCanceller) GetType() string {
	return new(netlink.Wireguard).Type()
}

func (wgInterfaceCanceller *WireGuardInterfaceCanceller) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return wgInterfaceCanceller.NetnsInfo, nil
}

func (wgInterfaceCanceller *WireGuardInterfaceCanceller) Cancel(ctx context.Context) error {
	return pkgnetns.WithNsHandleSafe(ctx, wgInterfaceCanceller, func(h *netlink.Handle) error {
		link, err := h.LinkByName(wgInterfaceCanceller.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get link by name to delete: %w", err)
		}
		if err := h.LinkDel(link); err != nil {
			return fmt.Errorf("failed to delete link: %w", err)
		}
		return nil
	})
}

func (changeSet *WireGuardResourceListChangeSet) GetAddedResources() []pkgreconcile.ResourceProvisioner {
	return changeSet.addedResources
}

func (changeSet *WireGuardResourceListChangeSet) GetRemovedResources() []pkgreconcile.ResourceCanceller {
	return changeSet.removedResources
}

func (changeSet *WireGuardResourceListChangeSet) GetUpdatedResources() []pkgreconcile.InterfaceChangeSet {
	return changeSet.updatedResources
}

func (changeSet *WireGuardResourceListChangeSet) HasUpdates() bool {
	if changeSet == nil {
		return false
	}

	return len(changeSet.addedResources) > 0 || len(changeSet.removedResources) > 0 || len(changeSet.updatedResources) > 0
}

func (wgCfgsList *WireGuardConfigurationList) GetType() string {
	return new(netlink.Wireguard).Type()
}

func (wgCfgsList *WireGuardConfigurationList) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	changeSet := new(WireGuardResourceListChangeSet)
	changeSet.addedResources = make([]pkgreconcile.ResourceProvisioner, 0)
	changeSet.removedResources = make([]pkgreconcile.ResourceCanceller, 0)
	changeSet.updatedResources = make([]pkgreconcile.InterfaceChangeSet, 0)

	// indexing specs, with netns key as the key
	specIndex := make(map[string]map[string]WireGuardConfig)
	for _, wgCfg := range wgCfgsList.WireGuardConfigs {
		if wgCfg.IsSoftDeleted() {
			continue
		}

		nsInfo, err := wgCfg.GetNetNsInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get netns info: %w", err)
		}
		netnsKey, err := nsInfo.ToNetnsKey()
		if err != nil {
			return nil, fmt.Errorf("failed to get netns key: %w", err)
		}
		if _, ok := specIndex[netnsKey]; !ok {
			specIndex[netnsKey] = make(map[string]WireGuardConfig)
		}
		specIndex[netnsKey][wgCfg.GetInterfaceName()] = wgCfg
	}

	var closureWrapper struct {
		commonSet map[string]map[string]*WireGuardConfig
	}
	closureWrapperPtr := &closureWrapper
	closureWrapperPtr.commonSet = make(map[string]map[string]*WireGuardConfig)
	for netnsKey := range specIndex {
		closureWrapperPtr.commonSet[netnsKey] = make(map[string]*WireGuardConfig)
	}

	ty := new(netlink.Wireguard).Type()
	err := pkgnetns.WithMultiNetnsHandle(ctx, wgCfgsList, func(h *netlink.Handle, netnsInfo *pkgnetns.NetNsInfo) error {
		netnsKey, err := netnsInfo.ToNetnsKey()
		if err != nil {
			return fmt.Errorf("failed to get netns key: %w", err)
		}

		superfluous := make([]*WireGuardInterfaceCanceller, 0)

		links, err := h.LinkList()
		for _, lk := range links {
			if lk.Type() != ty {
				continue
			}

			if m, ok := specIndex[netnsKey]; ok {
				if x, ok := m[lk.Attrs().Name]; !ok {
					closureWrapperPtr.commonSet[netnsKey][lk.Attrs().Name] = &x
					continue
				}
			}

			if delete {
				superfluous = append(superfluous, &WireGuardInterfaceCanceller{NetnsInfo: netnsInfo, InterfaceName: lk.Attrs().Name})
			}
		}

		for _, canceller := range superfluous {
			changeSet.removedResources = append(changeSet.removedResources, canceller)
		}

		return nil
	})

	for netnsKey, specs := range specIndex {
		for interfaceName, spec := range specs {
			if _, ok := closureWrapperPtr.commonSet[netnsKey][interfaceName]; !ok {
				changeSet.addedResources = append(changeSet.addedResources, &spec)
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

// An WireGuardConfigurationList is also an implementation of MultiNetnsResource interface.
func (wgCfgsList *WireGuardConfigurationList) GetNetNsInfos(ctx context.Context) ([]pkgnetns.NetNsInfo, error) {
	netnsInfos := make([]pkgnetns.NetNsInfo, 0)

	for _, container := range wgCfgsList.Containers {
		// currently, support only docker container

		cli, err := pkgutils.DockerCliFromCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get docker cli from context: %s", err)
		}

		pidPtr, err := pkgutils.GetContainerNSPid(ctx, cli, container)
		if err != nil {
			return nil, fmt.Errorf("resourcelist has declared a container but there is no way to obtain its pid: %s", err)
		}

		netnsInfos = append(netnsInfos, pkgnetns.NetNsInfo{Pid: pidPtr})
	}

	return netnsInfos, nil
}
