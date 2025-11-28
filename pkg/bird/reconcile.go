package bird

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgnetns "github.com/internetworklab/netapply/pkg/netns"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

const ResourceTypeBirdEBGPEBGP = "bird-ebgp"

type BirdEBGPRessourceListChangeSet struct {
	addedResources   []pkgreconcile.ResourceProvisioner
	removedResources []pkgreconcile.ResourceCanceller
	updatedResources []pkgreconcile.InterfaceChangeSet
}

func (changeSet *BirdEBGPRessourceListChangeSet) GetAddedResources() []pkgreconcile.ResourceProvisioner {
	return changeSet.addedResources
}

func (changeSet *BirdEBGPRessourceListChangeSet) GetRemovedResources() []pkgreconcile.ResourceCanceller {
	return changeSet.removedResources
}

func (changeSet *BirdEBGPRessourceListChangeSet) GetUpdatedResources() []pkgreconcile.InterfaceChangeSet {
	return changeSet.updatedResources
}

func (changeSet *BirdEBGPRessourceListChangeSet) HasUpdates() bool {
	if changeSet == nil {
		return false
	}

	return len(changeSet.addedResources) > 0 || len(changeSet.removedResources) > 0 || len(changeSet.updatedResources) > 0
}

func (bgpConfigList *BirdBGPConfigurationList) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	if bgpConfigList == nil {
		return nil, nil
	}

	directory, err := pkgutils.BirdBGPConfigDirFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get bird bgp config directory from context: %w", err)
	}
	if directory == "" {
		return nil, fmt.Errorf("bird bgp config directory is not set in context")
	}

	controlSocket, err := pkgutils.BirdControlSocketFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get bird control socket from context: %w", err)
	}
	if controlSocket == "" {
		return nil, fmt.Errorf("bird control socket is not set in context")
	}

	files, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", directory, err)
	}

	currResources := make(map[string]BGPProtocol)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name(), ConfigExtension) {
			continue
		}
		cfg, err := FromFile(filepath.Join(directory, file.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", filepath.Join(directory, file.Name()), err)
		}
		currResources[cfg.Name] = *cfg
	}

	specResources := make(map[string]BGPProtocol)
	for _, proto := range bgpConfigList.EBGPProtocols {
		if proto.IsSoftDeleted() {
			continue
		}

		specResources[proto.Name] = proto
	}

	changeSet := new(BirdEBGPRessourceListChangeSet)
	changeSet.addedResources = make([]pkgreconcile.ResourceProvisioner, 0)
	changeSet.removedResources = make([]pkgreconcile.ResourceCanceller, 0)
	changeSet.updatedResources = make([]pkgreconcile.InterfaceChangeSet, 0)

	commonResources := make(map[string]*BGPProtocol)

	for name, currRes := range currResources {
		if specRes, ok := specResources[name]; !ok || delete {
			changeSet.removedResources = append(changeSet.removedResources, &currRes)
		} else {
			commonResources[name] = &specRes
		}
	}

	for name, res := range specResources {
		if _, ok := currResources[name]; !ok {
			changeSet.addedResources = append(changeSet.addedResources, &res)
		}
	}

	for name, res := range commonResources {
		changes, err := res.DetectChanges(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes for protocol %s: %w", name, err)
		}
		if changes != nil && changes.HasUpdates() {
			changeSet.updatedResources = append(changeSet.updatedResources, changes)
		}
	}

	return changeSet, nil
}

func (bgpConfigList *BirdBGPConfigurationList) GetType() string {
	return ResourceTypeBirdEBGPEBGP
}

type BirdEBGPChangeSet struct {
	resource *BGPProtocol

	shouldUpdateTemplate     *string
	shouldUpdateInterface    *string
	shouldUpdateLocalAddress *string
	shouldUpdateLocalASN     *string
	shouldUpdatePeerAddress  *string
	shouldUpdatePeerASN      *string
	shouldUpdatePeerExternal *bool
	shouldUpdatePeerInternal *bool
}

func (changeSet *BirdEBGPChangeSet) Apply(ctx context.Context) error {
	if changeSet == nil || !changeSet.HasUpdates() {
		return nil
	}

	config, err := changeSet.resource.ToConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config for protocol %s: %w", changeSet.resource.Name, err)
	}

	fullpath, err := changeSet.resource.ToFilePath(ctx)
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", changeSet.resource.Name, err)
	}

	err = os.WriteFile(fullpath, []byte(config), 0644)
	if err != nil {
		return fmt.Errorf("failed to write config to file %s: %w", fullpath, err)
	}

	err = ReloadBirdConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("failed to reload bird configuration: %w", err)
	}

	return nil
}

func (changeSet *BirdEBGPChangeSet) HasUpdates() bool {
	if changeSet == nil {
		return false
	}

	return changeSet.shouldUpdateTemplate != nil ||
		changeSet.shouldUpdateInterface != nil ||
		changeSet.shouldUpdateLocalAddress != nil ||
		changeSet.shouldUpdateLocalASN != nil ||
		changeSet.shouldUpdatePeerAddress != nil ||
		changeSet.shouldUpdatePeerASN != nil ||
		changeSet.shouldUpdatePeerExternal != nil ||
		changeSet.shouldUpdatePeerInternal != nil
}

func (changeSet *BirdEBGPChangeSet) GetInterfaceName() string {
	return changeSet.resource.GetInterfaceName()
}

func (changeSet *BirdEBGPChangeSet) GetType() string {
	return ResourceTypeBirdEBGPEBGP
}

func ReloadBirdConfiguration(ctx context.Context) error {
	birdCtrlSocket, err := pkgutils.BirdControlSocketFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get bird control socket: %w", err)
	}
	birdCli := NewBirdClientFromSocket(birdCtrlSocket)
	if err := birdCli.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to bird: %w", err)
	}
	defer birdCli.Close()

	_, err = birdCli.SendOneOffCommand(ctx, "configure")
	if err != nil {
		return fmt.Errorf("failed to refresh protocol: %w", err)
	}

	return nil
}

func (proto *BGPProtocol) Create(ctx context.Context) error {

	config, err := proto.ToConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config for protocol %s: %w", proto.Name, err)
	}

	fullpath, err := proto.ToFilePath(ctx)
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}
	err = os.WriteFile(fullpath, []byte(config), 0644)
	if err != nil {
		return fmt.Errorf("failed to write config to file %s: %w", fullpath, err)
	}

	if err := ReloadBirdConfiguration(ctx); err != nil {
		return fmt.Errorf("failed to run reloader shell command: %w", err)
	}
	return nil
}

func (proto *BGPProtocol) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	fullpath, err := proto.ToFilePath(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}

	config, err := FromFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", fullpath, err)
	}

	changeSet := new(BirdEBGPChangeSet)
	changeSet.resource = proto

	if proto.Template != nil {
		if config.Template == nil || *config.Template != *proto.Template {
			changeSet.shouldUpdateTemplate = proto.Template
		}
	}

	if proto.Interface != nil {
		if config.Interface == nil || *config.Interface != *proto.Interface {
			changeSet.shouldUpdateInterface = proto.Interface
		}
	}

	if proto.LocalAddress != nil {
		if config.LocalAddress == nil || *config.LocalAddress != *proto.LocalAddress {
			changeSet.shouldUpdateLocalAddress = proto.LocalAddress
		}
	}

	if proto.LocalASN != nil {
		if config.LocalASN == nil || *config.LocalASN != *proto.LocalASN {
			changeSet.shouldUpdateLocalASN = proto.LocalASN
		}
	}

	if proto.PeerAddress != nil {
		if config.PeerAddress == nil || *config.PeerAddress != *proto.PeerAddress {
			changeSet.shouldUpdatePeerAddress = proto.PeerAddress
		}
	}

	if proto.PeerASN != nil {
		if config.PeerASN == nil || *config.PeerASN != *proto.PeerASN {
			changeSet.shouldUpdatePeerASN = proto.PeerASN
		}
	}

	if proto.PeerExternal != nil {
		if config.PeerExternal == nil || *config.PeerExternal != *proto.PeerExternal {
			changeSet.shouldUpdatePeerExternal = proto.PeerExternal
		}
	}

	if proto.PeerInternal != nil {
		if config.PeerInternal == nil || *config.PeerInternal != *proto.PeerInternal {
			changeSet.shouldUpdatePeerInternal = proto.PeerInternal
		}
	}

	return changeSet, nil
}

func (proto *BGPProtocol) GetInterfaceName() string {
	return proto.Name
}

func (proto *BGPProtocol) CheckExist(ctx context.Context) (bool, error) {
	fullpath, err := proto.ToFilePath(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}
	_, err = os.Stat(fullpath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to stat file %s: %w", fullpath, err)
	}
	return true, nil
}

func (proto *BGPProtocol) GetType() string {
	return ResourceTypeBirdEBGPEBGP
}

func (proto *BGPProtocol) IsSoftDeleted() bool {
	return proto.Deleted
}

func (proto *BGPProtocol) Cancel(ctx context.Context) error {
	fullpath, err := proto.ToFilePath(ctx)
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}

	err = os.Remove(fullpath)
	if err != nil {
		return fmt.Errorf("failed to remove config file %s: %w", fullpath, err)
	}

	if err := ReloadBirdConfiguration(ctx); err != nil {
		return fmt.Errorf("failed to run reloader shell command: %w", err)
	}
	return nil
}

func (proto *BGPProtocol) GetNetNsInfo(ctx context.Context) (*pkgnetns.NetNsInfo, error) {
	pid := os.Getpid()
	return &pkgnetns.NetNsInfo{Pid: &pid}, nil
}

func (proto *BGPProtocol) ToStatus(ctx context.Context) (pkginterfacestub.InterfaceStatus, error) {
	if proto == nil {
		return nil, fmt.Errorf("you are calling ToStatus on a nil BGPProtocol which is considered as an undefined behavior")
	}

	fullpath, err := proto.ToFilePath(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}

	config, err := FromFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", fullpath, err)
	}

	birdSocket, err := pkgutils.BirdControlSocketFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get bird control socket: %w", err)
	}
	birdCli := NewBirdClientFromSocket(birdSocket)
	if err := birdCli.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to bird: %w", err)
	}
	defer birdCli.Close()
	protocolStatus, err := birdCli.ShowBGPProtocolInfo(ctx, proto.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get bird protocol status: %w", err)
	}

	status := &BirdBGPProtocolStatus{
		CurrentConfig:  config,
		ProtocolStatus: protocolStatus,
	}
	return status, nil
}

func (bgpProto *BGPProtocol) IsEqual(other *BGPProtocol) bool {
	if bgpProto == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	if bgpProto.Name != other.Name {
		return false
	}
	if !pkgutils.CompareStringPointers(bgpProto.Template, other.Template) {
		return false
	}
	if !pkgutils.CompareStringPointers(bgpProto.Interface, other.Interface) {
		return false
	}
	if !pkgutils.CompareStringPointers(bgpProto.LocalAddress, other.LocalAddress) {
		return false
	}
	if !pkgutils.CompareStringPointers(bgpProto.PeerAddress, other.PeerAddress) {
		return false
	}
	if !pkgutils.CompareStringPointers(bgpProto.LocalASN, other.LocalASN) {
		return false
	}
	if !pkgutils.CompareStringPointers(bgpProto.PeerASN, other.PeerASN) {
		return false
	}
	if !pkgutils.CompareBoolPointers(bgpProto.PeerExternal, other.PeerExternal) {
		return false
	}
	if !pkgutils.CompareBoolPointers(bgpProto.PeerInternal, other.PeerInternal) {
		return false
	}
	return true
}

func (bgpStatus *BirdBGPProtocolStatus) IsEqual(other pkginterfacestub.InterfaceStatus) bool {
	if bgpStatus == nil {
		return other == nil
	}
	if other == nil {
		return false
	}
	rhs, ok := other.(*BirdBGPProtocolStatus)
	if !ok {
		return false
	}
	if rhs == nil {
		return false
	}
	if !bgpStatus.CurrentConfig.IsEqual(rhs.CurrentConfig) {
		return false
	}
	if !bgpStatus.ProtocolStatus.IsEqual(rhs.ProtocolStatus) {
		return false
	}
	return true
}

func (bgpProto *BGPProtocol) Delete(ctx context.Context) error {
	filePath, err := bgpProto.ToFilePath(ctx)
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", bgpProto.Name, err)
	}

	err = os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("failed to remove config file %s: %w", filePath, err)
	}

	if err := ReloadBirdConfiguration(ctx); err != nil {
		return fmt.Errorf("failed to run reloader shell command: %w", err)
	}
	return nil
}
