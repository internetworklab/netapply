package bird

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
)

const ResourceTypeBirdEBGPEBGP = "bird-ebgp"

type BirdEBGPRessourceListChangeSet struct {
	addedResources   map[string]pkgreconcile.ResourceProvisioner
	removedResources map[string]pkgreconcile.ResourceCanceller
	updatedResources map[string]pkgreconcile.InterfaceChangeSet
}

func (changeSet *BirdEBGPRessourceListChangeSet) GetAddedResources() map[string]pkgreconcile.ResourceProvisioner {
	return changeSet.addedResources
}

func (changeSet *BirdEBGPRessourceListChangeSet) GetRemovedResources() map[string]pkgreconcile.ResourceCanceller {
	return changeSet.removedResources
}

func (changeSet *BirdEBGPRessourceListChangeSet) GetUpdatedResources() map[string]pkgreconcile.InterfaceChangeSet {
	return changeSet.updatedResources
}

func (changeSet *BirdEBGPRessourceListChangeSet) HasUpdates() bool {
	if changeSet == nil {
		return false
	}

	return len(changeSet.addedResources) > 0 || len(changeSet.removedResources) > 0 || len(changeSet.updatedResources) > 0
}

func (bgpConfigList *BirdBGPConfigurationList) DetectChanges(ctx context.Context, delete bool) (pkgreconcile.ResourceListChangeSet, error) {
	directory := bgpConfigList.TargetConfigDirectory
	if directory == "" {
		return nil, fmt.Errorf("bird bgp config directory is not set")
	}
	reloaderShellCommand := bgpConfigList.ReloaderShellCommand
	if reloaderShellCommand == nil {
		return nil, fmt.Errorf("bird bgp reloader shell command is not set")
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
		cfg.Reloader = reloaderShellCommand
		cfg.ConfigDirectory = directory

		currResources[cfg.Name] = *cfg
	}

	specResources := make(map[string]BGPProtocol)
	for _, proto := range bgpConfigList.EBGPProtocols {
		proto.Reloader = reloaderShellCommand
		proto.ConfigDirectory = directory
		specResources[proto.Name] = proto
	}

	changeSet := new(BirdEBGPRessourceListChangeSet)
	changeSet.addedResources = make(map[string]pkgreconcile.ResourceProvisioner)
	changeSet.removedResources = make(map[string]pkgreconcile.ResourceCanceller)
	changeSet.updatedResources = make(map[string]pkgreconcile.InterfaceChangeSet)

	commonResources := make(map[string]*BGPProtocol)

	for name, res := range currResources {
		if _, ok := specResources[name]; !ok {
			changeSet.removedResources[name] = &res
		} else {
			commonResources[name] = &res
		}
	}

	for name, res := range specResources {
		if _, ok := currResources[name]; !ok {
			changeSet.addedResources[name] = &res
		}
	}

	for name, res := range commonResources {
		changes, err := res.DetectChanges(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to detect changes for protocol %s: %w", name, err)
		}
		if changes != nil && changes.HasUpdates() {
			changeSet.updatedResources[name] = changes
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

	fullpath, err := changeSet.resource.ToFilePath()
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", changeSet.resource.Name, err)
	}

	err = os.WriteFile(fullpath, []byte(config), 0644)
	if err != nil {
		return fmt.Errorf("failed to write config to file %s: %w", fullpath, err)
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

func (proto *BGPProtocol) Create(ctx context.Context) error {

	config, err := proto.ToConfig()
	if err != nil {
		return fmt.Errorf("failed to generate config for protocol %s: %w", proto.Name, err)
	}

	fullpath, err := proto.ToFilePath()
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}
	err = os.WriteFile(fullpath, []byte(config), 0644)
	if err != nil {
		return fmt.Errorf("failed to write config to file %s: %w", fullpath, err)
	}

	reloaderShellCommand := proto.Reloader
	if reloaderShellCommand == nil {
		return fmt.Errorf("bird bgp reloader shell command is not set")
	}

	command := exec.Command(reloaderShellCommand[0], reloaderShellCommand[1:]...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("failed to run reloader shell command: %w", err)
	}
	return nil
}

func (proto *BGPProtocol) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	fullpath, err := proto.ToFilePath()
	if err != nil {
		return nil, fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}

	config, err := FromFile(fullpath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", fullpath, err)
	}

	changeSet := new(BirdEBGPChangeSet)
	changeSet.resource = config

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
	fullpath, err := proto.ToFilePath()
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
	fullpath, err := proto.ToFilePath()
	if err != nil {
		return fmt.Errorf("failed to get file path for protocol %s: %w", proto.Name, err)
	}

	err = os.Remove(fullpath)
	if err != nil {
		return fmt.Errorf("failed to remove config file %s: %w", fullpath, err)
	}

	reloaderShellCommand := proto.Reloader
	if reloaderShellCommand == nil {
		return fmt.Errorf("bird bgp reloader shell command is not set")
	}

	command := exec.Command(reloaderShellCommand[0], reloaderShellCommand[1:]...)
	if err := command.Run(); err != nil {
		return fmt.Errorf("failed to run reloader shell command: %w", err)
	}
	return nil
}
