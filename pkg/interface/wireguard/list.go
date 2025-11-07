package wireguard

import (
	"context"

	"fmt"

	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

func (wgCfgsList *WireGuardConfigurationList) GetType() string {
	return new(netlink.Wireguard).Type()
}

func (wgCfgsList *WireGuardConfigurationList) GetProvisioners() []pkginterfacestub.NetnsIdentifiableProvisioner {
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
