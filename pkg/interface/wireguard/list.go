package wireguard

import (
	"context"

	"fmt"

	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	"github.com/vishvananda/netlink"
)

func (wgCfgsList *WireGuardConfigurationList) GetType() string {
	return new(netlink.Wireguard).Type()
}

func (wgCfgsList *WireGuardConfigurationList) GetProvisioners() []pkginterfacestub.NetnsIdentifiableProvisioner {
	if wgCfgsList == nil {
		return nil
	}

	provisioners := make([]pkginterfacestub.NetnsIdentifiableProvisioner, 0)
	for _, wgCfg := range wgCfgsList.WireGuardConfigs {
		if wgCfg.IsSoftDeleted() {
			continue
		}
		provisioners = append(provisioners, &wgCfg)
	}
	return provisioners
}

func (wgCfgsList *WireGuardConfigurationList) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	return pkginterfacestub.DetectChanges(ctx, wgCfgsList, delete)
}

// An WireGuardConfigurationList is also an implementation of MultiNetnsResource interface.
func (wgCfgsList *WireGuardConfigurationList) GetNetNsInfos(ctx context.Context) ([]pkgnetns.NetNsInfo, error) {
	if wgCfgsList == nil {
		return nil, nil
	}

	netnsInfos := make([]pkgnetns.NetNsInfo, 0)

	for _, container := range wgCfgsList.Containers {
		netnsInfo, err := container.GetNetNsInfo(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get netns info: %w", err)
		}
		netnsInfos = append(netnsInfos, *netnsInfo)
	}

	return netnsInfos, nil
}
