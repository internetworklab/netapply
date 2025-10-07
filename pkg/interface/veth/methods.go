package veth

import (
	"context"
	"fmt"
	"strings"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

func (vethPair *VethPairChangeSet) GetChangedItems() map[string]bool {
	changedItems := make(map[string]bool)
	for k, v := range vethPair.Local.GetChangedItems() {
		changedItems["local."+k] = v
	}
	for k, v := range vethPair.Peer.GetChangedItems() {
		changedItems["peer."+k] = v
	}
	return changedItems
}

func (vethPair *VethPairChangeSet) GetContainerName() *string {
	return vethPair.Local.ContainerName
}

func (vethPair *VethPairChangeSet) GetInterfaceName() string {
	return vethPair.Local.InterfaceName
}

func (vethPair *VethPairChangeSet) HasUpdates() bool {
	return vethPair != nil && (vethPair.Local.HasUpdates() || vethPair.Peer.HasUpdates())
}

func (vethPair *VethPairChangeSet) Apply(ctx context.Context) error {
	if vethPair != nil {
		if err := vethPair.Local.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply local veth pair: %w", err)
		}
		if err := vethPair.Peer.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply peer veth pair: %w", err)
		}
		return nil
	}

	return nil
}

func (vethPeer *VethPairPeerChangeSet) GetChangedItems() map[string]bool {
	changedItems := make(map[string]bool)
	changedItems["Addresses"] = len(vethPeer.AddressesToAdd)+len(vethPeer.AddressesToDel) > 0
	changedItems["MTU"] = vethPeer.MTUToSet != nil
	return changedItems
}

func (vethPeer *VethPairPeerChangeSet) HasUpdates() bool {
	return vethPeer != nil && (len(vethPeer.AddressesToAdd) > 0 || len(vethPeer.AddressesToDel) > 0 || vethPeer.MTUToSet != nil)
}

func (vethPeer *VethPairPeerChangeSet) Apply(ctx context.Context) error {
	if vethPeer == nil {
		return nil
	}

	return pkgdocker.WithNsHandleSafe(ctx, vethPeer.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vethPeer.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get veth link: %w", err)
		}

		for _, addr := range vethPeer.AddressesToDel {
			if err := handle.AddrDel(link, addr); err != nil {
				return fmt.Errorf("failed to remove address from veth link: %w", err)
			}
		}

		for _, addr := range vethPeer.AddressesToAdd {
			if err := handle.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add address to veth link: %w", err)
			}
		}

		if vethPeer.MTUToSet != nil {
			if err := handle.LinkSetMTU(link, *vethPeer.MTUToSet); err != nil {
				return fmt.Errorf("failed to set veth link mtu: %w", err)
			}
		}

		return nil
	})
}

func NewVethPairPeerChangeSet(containerName *string, interfaceName string, spec *VethPairConfig, handle *netlink.Handle) (*VethPairPeerChangeSet, error) {

	changeSet := new(VethPairPeerChangeSet)
	changeSet.ContainerName = containerName
	changeSet.InterfaceName = interfaceName

	link, err := handle.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth link: %w", err)
	}

	if spec.MTU != nil {
		if *spec.MTU != link.Attrs().MTU {
			changeSet.MTUToSet = spec.MTU
		}
	}

	addrsChangeSet, err := pkginterfacecommon.CompareSpecAddrsAgainstActualAddrs(spec.Addresses, link, handle)
	if err != nil {
		return nil, fmt.Errorf("failed to compare spec addrs against actual addrs: %w", err)
	}
	changeSet.AddressesToAdd = addrsChangeSet.AddressesToAdd
	changeSet.AddressesToDel = addrsChangeSet.AddressesToRemove

	return changeSet, nil
}

func (vethPairConfig *VethPairConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	changeSet := new(VethPairChangeSet)

	// Detecting local changeset
	err := pkgdocker.WithNsHandleSafe(ctx, vethPairConfig.ContainerName, func(handle *netlink.Handle) error {
		localChangeSet, err := NewVethPairPeerChangeSet(vethPairConfig.ContainerName, vethPairConfig.Name, vethPairConfig, handle)
		if err != nil {
			return fmt.Errorf("failed to detect local changeset: %w", err)
		}
		changeSet.Local = localChangeSet
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	// Detecting peer changeset
	err = pkgdocker.WithNsHandleSafe(ctx, vethPairConfig.Peer.ContainerName, func(handle *netlink.Handle) error {
		peerChangeSet, err := NewVethPairPeerChangeSet(vethPairConfig.Peer.ContainerName, vethPairConfig.Peer.Name, vethPairConfig.Peer, handle)
		if err != nil {
			return fmt.Errorf("failed to detect peer changeset: %w", err)
		}
		changeSet.Peer = peerChangeSet
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	return changeSet, err
}

func (vethPairConfig *VethPairConfig) GetContainerName() *string {
	return vethPairConfig.ContainerName
}

func (vethPairConfig *VethPairConfig) GetInterfaceName() string {
	return vethPairConfig.Name
}

func (vethPairConfig *VethPairConfig) Create(ctx context.Context) error {

	return pkgdocker.WithNsHandleSafe(ctx, nil, func(handle *netlink.Handle) error {
		cli, err := pkgutils.DockerCliFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get docker cli from context: %w", err)
		}

		if vethPairConfig.Peer == nil {
			return fmt.Errorf("peer is not set")
		}

		link := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: vethPairConfig.Name,
			},
			PeerName: vethPairConfig.Peer.Name,
		}

		if vethPairConfig.ContainerName != nil {
			pidPtr, err := pkgdocker.GetContainerNSPid(ctx, cli, *vethPairConfig.ContainerName)
			if err != nil {
				return fmt.Errorf("failed to get container ns pid: %w", err)
			}
			if pidPtr != nil {
				link.Namespace = netlink.NsPid(*pidPtr)
			}
		}

		if vethPairConfig.Peer.ContainerName != nil {
			pidPtr, err := pkgdocker.GetContainerNSPid(ctx, cli, *vethPairConfig.Peer.ContainerName)
			if err != nil {
				return fmt.Errorf("failed to get container ns pid: %w", err)
			}
			if pidPtr != nil {
				link.PeerNamespace = netlink.NsPid(*pidPtr)
			}
		}

		err = handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add veth link: %w", err)
		}

		err = pkgdocker.WithNsHandle(ctx, vethPairConfig.ContainerName, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(vethPairConfig.Name)
			if err != nil {
				return fmt.Errorf("failed to get veth link: %w", err)
			}

			for _, addr := range vethPairConfig.Addresses {
				nlAddr, err := addr.ToNetlinkAddr()
				if err != nil {
					return fmt.Errorf("failed to convert address to netlink addr: %w", err)
				}
				if err := handle.AddrAdd(link, nlAddr); err != nil {
					return fmt.Errorf("failed to add address to veth link: %w", err)
				}
			}

			return handle.LinkSetUp(link)
		})
		if err != nil {
			return fmt.Errorf("failed to set veth link up (lhs): %w", err)
		}

		err = pkgdocker.WithNsHandle(ctx, vethPairConfig.Peer.ContainerName, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(vethPairConfig.Peer.Name)
			if err != nil {
				return fmt.Errorf("failed to get veth link: %w", err)
			}

			if vethPairConfig.Peer != nil {
				for _, addr := range vethPairConfig.Peer.Addresses {
					nlAddr, err := addr.ToNetlinkAddr()
					if err != nil {
						return fmt.Errorf("failed to convert address to netlink addr: %w", err)
					}
					if err := handle.AddrAdd(link, nlAddr); err != nil {
						return fmt.Errorf("failed to add address to veth link: %w", err)
					}
				}
			}

			return handle.LinkSetUp(link)
		})
		if err != nil {
			return fmt.Errorf("failed to set veth link up (rhs): %w", err)
		}

		return nil
	})
}

func (vethPairConfig *VethPairConfig) GetPlacementStatus(ctx context.Context) (*VethPairPlacementStatus, error) {
	res := new(VethPairPlacementStatus)

	pkgdocker.WithNsHandleSafe(ctx, vethPairConfig.GetContainerName(), func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vethPairConfig.GetInterfaceName())
		if err == nil && link != nil {
			res.FoundInPrimaryNetns = true
		}
		return nil
	})

	pkgdocker.WithNsHandleSafe(ctx, vethPairConfig.Peer.GetContainerName(), func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vethPairConfig.Peer.GetInterfaceName())
		if err == nil && link != nil {
			res.FoundInSecondaryNetns = true
		}
		return nil
	})

	return res, nil
}

func (vethPairList VethPairConfigurationList) DetectChanges(ctx context.Context, containers []string) (*pkgreconcile.DataplaneChangeSet, error) {
	vethPairsToCreate := make([]VethPairConfig, 0)
	vethPairsToDelete := make([]pkgreconcile.InterfaceCanceller, 0)
	vethPairsToCheckUpdates := make([]VethPairConfig, 0)
	vethPairsUpdated := make([]pkgreconcile.InterfaceChangeSet, 0)

	vethSpecMap := make(map[string]map[string]interface{})

	for _, vethPairSpec := range vethPairList {
		nsKey := string(pkgdocker.GetContainerKey(vethPairSpec.GetContainerName()))
		if _, ok := vethSpecMap[nsKey]; !ok {
			vethSpecMap[nsKey] = make(map[string]interface{})
		}
		vethSpecMap[nsKey][vethPairSpec.GetInterfaceName()] = true
		secondaryNsKey := string(pkgdocker.GetContainerKey(vethPairSpec.Peer.GetContainerName()))
		if _, ok := vethSpecMap[secondaryNsKey]; !ok {
			vethSpecMap[secondaryNsKey] = make(map[string]interface{})
		}
		vethSpecMap[secondaryNsKey][vethPairSpec.Peer.GetInterfaceName()] = true

		placementStatus, err := vethPairSpec.GetPlacementStatus(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get placement status for veth pair %s: %w", vethPairSpec.Name, err)
		}

		if placementStatus.FoundInPrimaryNetns && placementStatus.FoundInSecondaryNetns {
			vethPairsToCheckUpdates = append(vethPairsToCheckUpdates, vethPairSpec)
		} else if !placementStatus.FoundInPrimaryNetns && !placementStatus.FoundInSecondaryNetns {
			vethPairsToCreate = append(vethPairsToCreate, vethPairSpec)
		} else if placementStatus.FoundInPrimaryNetns && !placementStatus.FoundInSecondaryNetns {
			vethPairsToDelete = append(vethPairsToDelete, &pkginterfacestub.StubInterfaceCanceller{ContainerName: vethPairSpec.GetContainerName(), InterfaceName: vethPairSpec.GetInterfaceName()})
			vethPairsToCreate = append(vethPairsToCreate, vethPairSpec)
		} else if !placementStatus.FoundInPrimaryNetns && placementStatus.FoundInSecondaryNetns {
			vethPairsToDelete = append(vethPairsToDelete, &pkginterfacestub.StubInterfaceCanceller{ContainerName: vethPairSpec.Peer.GetContainerName(), InterfaceName: vethPairSpec.Peer.GetInterfaceName()})
			vethPairsToCreate = append(vethPairsToCreate, vethPairSpec)
		} else {
			continue
		}
	}

	for _, vethPairSpec := range vethPairsToCheckUpdates {
		changes, err := vethPairSpec.DetectChanges(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes for veth pair %s: %w", vethPairSpec.Name, err)
		}
		if changes != nil && changes.HasUpdates() {
			vethPairsUpdated = append(vethPairsUpdated, changes)
		}
	}

	vethTy := new(netlink.Veth).Type()
	for _, cont := range containers {
		err := pkgdocker.WithNsHandleSafe(ctx, &cont, func(handle *netlink.Handle) error {
			links, err := handle.LinkList()
			if err != nil {
				return fmt.Errorf("failed to list links: %w", err)
			}

			for _, link := range links {
				if strings.HasPrefix(link.Attrs().Name, "eth") || strings.HasPrefix(link.Attrs().Name, "lo") {
					continue
				}

				if link.Type() != vethTy {
					continue
				}

				if ifmap, ok := vethSpecMap[cont]; ok {
					if _, ok := ifmap[link.Attrs().Name]; ok {
						continue
					}
				}
				vethPairsToDelete = append(vethPairsToDelete, &pkginterfacestub.StubInterfaceCanceller{ContainerName: &cont, InterfaceName: link.Attrs().Name})
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list links for container %s: %w", cont, err)
		}
	}

	changeSet := new(pkgreconcile.DataplaneChangeSet)
	changeSet.AddedInterfaces = make(map[string][]pkgreconcile.InterfaceProvisioner)
	changeSet.UpdatedInterfaces = make(map[string][]pkgreconcile.InterfaceChangeSet)
	changeSet.RemovedInterfaces = make(map[string][]pkgreconcile.InterfaceCanceller)

	for _, vethPairSpec := range vethPairsToCreate {
		nsKey := string(pkgdocker.GetContainerKey(vethPairSpec.GetContainerName()))
		changeSet.AddedInterfaces[nsKey] = append(changeSet.AddedInterfaces[nsKey], &vethPairSpec)
	}

	for _, vethPairSpec := range vethPairsToDelete {
		nsKey := string(pkgdocker.GetContainerKey(vethPairSpec.GetContainerName()))
		changeSet.RemovedInterfaces[nsKey] = append(changeSet.RemovedInterfaces[nsKey], vethPairSpec)
	}

	for _, vethPairSpec := range vethPairsUpdated {
		nsKey := string(pkgdocker.GetContainerKey(vethPairSpec.GetContainerName()))
		changeSet.UpdatedInterfaces[nsKey] = append(changeSet.UpdatedInterfaces[nsKey], vethPairSpec)
	}

	return changeSet, nil
}
