package vrf

import (
	"context"

	"fmt"

	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	netlink "github.com/vishvananda/netlink"
)

func (vrfList *VRFConfigurationList) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	return pkginterfacestub.DetectChanges(ctx, vrfList, delete)
}

func (vrfList *VRFConfigurationList) GetType() string {
	return new(netlink.Vrf).Type()
}

func (vrfList *VRFConfigurationList) GetProvisioners() []pkginterfacestub.NetnsIdentifiableProvisioner {
	if vrfList == nil {
		return nil
	}
	provisioners := make([]pkginterfacestub.NetnsIdentifiableProvisioner, 0)
	for _, vrfCfg := range vrfList.VRFs {
		if vrfCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &vrfCfg)
	}
	return provisioners
}

func (vrfList *VRFConfigurationList) GetNetNsInfos(ctx context.Context) ([]pkgnetns.NetNsInfo, error) {
	if vrfList == nil {
		return nil, nil
	}

	netnsInfos := make([]pkgnetns.NetNsInfo, 0)
	for _, container := range vrfList.Containers {
		netnsInfo, err := container.GetNetNsInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get netns info: %w", err)
		}
		netnsInfos = append(netnsInfos, *netnsInfo)
	}

	return netnsInfos, nil
}
