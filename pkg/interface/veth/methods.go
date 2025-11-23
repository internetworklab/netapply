package veth

import (
	"context"
	"fmt"

	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

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

func (vethPeer *VethPairPeerChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	// todo
	return nil, nil
}

func (vethPeer *VethPairPeerChangeSet) Apply(ctx context.Context) error {
	if vethPeer == nil {
		return nil
	}

	return pkgnetns.WithNsHandleSafe(ctx, vethPeer, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vethPeer.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get veth link: %w", err)
		}

		if vethPeer.VRFToSet != nil {
			if err := pkgutils.TrySetVRF(handle, link, vethPeer.VRFToSet); err != nil {
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

func NewVethPairPeerChangeSet(spec *VethPairConfig, handle *netlink.Handle) (*VethPairPeerChangeSet, error) {

	if spec.Stub {
		// stub interface never actually reconciles
		return nil, nil
	}

	changeSet := new(VethPairPeerChangeSet)

	link, err := handle.LinkByName(spec.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth link: %w", err)
	}

	if spec.VRF != nil {
		if changeSet.VRFToSet, err = pkgutils.CheckVRFDiff(handle, link, spec.VRF); err != nil {
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

func (vChangeSet *VethPairChangeSet) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return vChangeSet.Local.GetNetNsInfo(ctx)
}

func (vethPairConfig *VethPairConfig) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	if vethPairConfig.Stub {
		// stub interface never actually reconciles
		return nil, nil
	}

	changeSet := new(VethPairChangeSet)

	// Detecting local changeset
	err := pkgnetns.WithNsHandleSafe(ctx, vethPairConfig, func(handle *netlink.Handle) error {
		localChangeSet, err := NewVethPairPeerChangeSet(vethPairConfig, handle)
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
	err = pkgnetns.WithNsHandleSafe(ctx, vethPairConfig.Peer, func(handle *netlink.Handle) error {
		peerChangeSet, err := NewVethPairPeerChangeSet(vethPairConfig.Peer, handle)
		if err != nil {
			return fmt.Errorf("failed to detect peer changeset: %w", err)
		}
		changeSet.Peer = peerChangeSet
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	return changeSet, nil
}

func (vethPairConfig *VethPairConfig) GetInterfaceName() string {
	return vethPairConfig.Name
}

// Returns a netlink.NsPid or netlink.NsFd or nil
func toLinkNetNs(netnsInfo *pkgnetns.NetNsInfo) interface{} {
	if netnsInfo.Pid != nil {
		return netlink.NsPid(*netnsInfo.Pid)
	} else if netnsInfo.NetNsPath != nil {
		hdl, err := netns.GetFromPath(*netnsInfo.NetNsPath)
		if err != nil {
			panic("can't get netns (aka netns fd) handle from path")
		}
		return netlink.NsFd(hdl)
	}
	return nil
}

func (vethPairConfig *VethPairConfig) Create(ctx context.Context) error {
	if vethPairConfig.Stub {
		// stub interface never actually creates or reconciles
		return nil
	}

	primaryNetnsInfo, err := vethPairConfig.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get primary netns info: %w", err)
	}

	secondaryNetnsInfo, err := vethPairConfig.Peer.GetNetNsInfo(ctx)
	if err != nil {
		return fmt.Errorf("failed to get secondary netns info: %w", err)
	}

	return pkgnetns.WithNsHandleSafe(ctx, nil, func(handle *netlink.Handle) error {
		if vethPairConfig.Peer == nil {
			return fmt.Errorf("peer is not set")
		}

		link := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: vethPairConfig.Name,
			},
			PeerName: vethPairConfig.Peer.Name,
		}

		if primaryNetnsInfo != nil {
			link.Namespace = toLinkNetNs(primaryNetnsInfo)
		}

		if secondaryNetnsInfo != nil {
			link.PeerNamespace = toLinkNetNs(secondaryNetnsInfo)
		}

		err := handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add veth link: %w", err)
		}

		err = pkgnetns.WithNsHandleSafe(ctx, vethPairConfig, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(vethPairConfig.Name)
			if err != nil {
				return fmt.Errorf("failed to get veth link: %w", err)
			}

			if vethPairConfig.VRF != nil {
				if err := pkgutils.TrySetVRF(handle, link, vethPairConfig.VRF); err != nil {
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

		err = pkgnetns.WithNsHandleSafe(ctx, vethPairConfig.Peer, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(vethPairConfig.Peer.Name)
			if err != nil {
				return fmt.Errorf("failed to get veth link: %w", err)
			}

			if vethPairConfig.Peer != nil {

				if vethPairConfig.Peer.VRF != nil {
					if err := pkgutils.TrySetVRF(handle, link, vethPairConfig.Peer.VRF); err != nil {
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

func (vethCfgsList *VethPairConfigurationList) GetProvisioners() []pkginterfacestub.NetnsIdentifiableProvisioner {
	if vethCfgsList == nil {
		return nil
	}
	provisioners := make([]pkginterfacestub.NetnsIdentifiableProvisioner, 0)
	for _, vethCfg := range vethCfgsList.VethPairs {
		if vethCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &vethCfg)
	}
	return provisioners
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

func (vethCfgsList *VethPairConfigurationList) GetNetNsInfos(ctx context.Context) ([]pkgnetns.NetNsInfo, error) {
	if vethCfgsList == nil {
		return nil, nil
	}
	netnsInfos := make([]pkgnetns.NetNsInfo, 0)
	for _, container := range vethCfgsList.Containers {
		netnsInfo, err := container.GetNetNsInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get netns info: %w", err)
		}
		netnsInfos = append(netnsInfos, *netnsInfo)
	}
	return netnsInfos, nil
}

func (vethCfgsList *VethPairConfigurationList) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	return pkginterfacestub.DetectChanges(ctx, vethCfgsList, delete)
}

func (vethPairSpec *VethPairConfig) IsSoftDeleted() bool {
	return vethPairSpec.Deleted
}

func (vethPairSpec *VethPairConfig) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	return vethPairSpec.Container.GetNetNsInfo(ctx)
}
