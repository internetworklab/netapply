package veth

import (
	"context"
	"fmt"

	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkginterfacevrf "github.com/internetworklab/netapply/pkg/interface/vrf"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

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

func (vethPeer *VethPairPeerChangeSet) HasUpdates() bool {
	return vethPeer != nil && (len(vethPeer.AddressesToAdd) > 0 || len(vethPeer.AddressesToDel) > 0 || vethPeer.MTUToSet != nil || vethPeer.VRFToSet != nil)
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

		if vethPeer.VRFToSet != nil {
			if err := pkginterfacevrf.TrySetVRF(handle, link, vethPeer.VRFToSet); err != nil {
				return fmt.Errorf("failed to set vrf for veth link: %w", err)
			}
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

	if spec.Stub {
		// stub interface never actually reconciles
		return nil, nil
	}

	changeSet := new(VethPairPeerChangeSet)
	changeSet.ContainerName = containerName
	changeSet.InterfaceName = interfaceName

	link, err := handle.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth link: %w", err)
	}

	if spec.VRF != nil {
		if changeSet.VRFToSet, err = pkginterfacevrf.CheckVRFDiff(handle, link, spec.VRF); err != nil {
			return nil, fmt.Errorf("failed to check vrf diff: %w", err)
		}
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
	if vethPairConfig.Stub {
		// stub interface never actually reconciles
		return nil, nil
	}

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
	if vethPairConfig.Stub {
		// stub interface never actually creates or reconciles
		return nil
	}

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

			if vethPairConfig.VRF != nil {
				if err := pkginterfacevrf.TrySetVRF(handle, link, vethPairConfig.VRF); err != nil {
					return fmt.Errorf("failed to set vrf for veth link: %w", err)
				}
			}

			if vethPairConfig.MTU != nil {
				if err := handle.LinkSetMTU(link, *vethPairConfig.MTU); err != nil {
					return fmt.Errorf("failed to set veth link mtu: %w", err)
				}
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

				if vethPairConfig.Peer.VRF != nil {
					if err := pkginterfacevrf.TrySetVRF(handle, link, vethPairConfig.Peer.VRF); err != nil {
						return fmt.Errorf("failed to set vrf for veth link: %w", err)
					}
				}

				if vethPairConfig.Peer.MTU != nil {
					if err := handle.LinkSetMTU(link, *vethPairConfig.Peer.MTU); err != nil {
						return fmt.Errorf("failed to set veth link mtu: %w", err)
					}
				}

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

func (vethCfgsList *VethPairConfigurationList) GetType() string {
	return new(netlink.Veth).Type()
}

func (vethCfgsList *VethPairConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	if vethCfgsList == nil {
		return nil
	}
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, vethCfg := range vethCfgsList.VethPairs {
		provisioners = append(provisioners, &vethCfg)
	}
	return provisioners
}

func (vethCfgsList *VethPairConfigurationList) IndexCurrentResources(ctx context.Context) (map[string]map[string]pkgreconcile.ResourceCanceller, error) {
	if vethCfgsList == nil {
		return nil, nil
	}
	return pkgreconcile.IndexStubNetlinkInterfaceList(ctx, vethCfgsList)
}

func (vethCfgsList *VethPairConfigurationList) GetContainers() []string {
	if vethCfgsList == nil {
		return nil
	}
	return vethCfgsList.Containers
}

func (vethCfgsList *VethPairConfigurationList) CheckResourceExistInSpec(ctx context.Context, specsMap map[string]map[string]pkgreconcile.ResourceProvisioner, resource pkgreconcile.ResourceCanceller) (bool, error) {
	if vethCfgsList == nil {
		return false, nil
	}
	return pkgreconcile.CheckResourceExistInSpec(ctx, specsMap, resource)
}

func (vethPairSpec *VethPairConfig) GetType() string {
	return new(netlink.Veth).Type()
}

func (vethPairSpec *VethPairConfig) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, vethPairSpec)
}

func (vethPairChangeSet *VethPairChangeSet) GetType() string {
	return new(netlink.Veth).Type()
}
