package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"gopkg.in/yaml.v3"
)

const WGConfigFileExtension = ".conf"
const WGMaskFileExtension = ".mask"

var (
	ContainerName string
	WGConfsDir    string
)

func main() {
	flag.Parse()

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get current working directory: %v", err)
	}

	wgdir := filepath.Join(cwd, "wg")
	if len(WGConfsDir) > 0 {
		if filepath.IsAbs(WGConfsDir) {
			wgdir = WGConfsDir
		} else {
			wgdir = filepath.Join(cwd, WGConfsDir)
		}
	}

	iniAdapter := new(pkginterfacewireguard.ExtendedINIWireGuardConfigAdapter)

	nodeCfgs := new(pkgmodels.NodeConfig)

	err = filepath.WalkDir(wgdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		if strings.HasSuffix(path, WGMaskFileExtension) {
			return nil
		}

		if !strings.HasSuffix(path, WGConfigFileExtension) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		basename := filepath.Base(path)
		instanceName := strings.TrimSuffix(basename, WGConfigFileExtension)

		wgConf, err := iniAdapter.ToWireGuardConfig(content)
		if err != nil {
			return fmt.Errorf("failed to convert WireGuard config to WireGuardConfig: %w", err)
		}

		if nodeCfgs.Resources == nil {
			nodeCfgs.Resources = new(pkgmodels.ResourcesConfig)
		}
		if nodeCfgs.Resources.WireGuard == nil {
			nodeCfgs.Resources.WireGuard = new(pkginterfacewireguard.WireGuardConfigurationList)
		}

		wgConf.Name = instanceName
		nodeCfgs.Resources.WireGuard.WireGuardConfigs = append(nodeCfgs.Resources.WireGuard.WireGuardConfigs, *wgConf)

		return nil
	})

	if err != nil {
		log.Fatalf("failed to walk directory: %v", err)
	}

	if ContainerName != "" {
		if nodeCfgs.Resources != nil {
			if nodeCfgs.Resources.WireGuard != nil {
				nodeCfgs.Resources.WireGuard.Containers = []string{ContainerName}
				for i := range nodeCfgs.Resources.WireGuard.WireGuardConfigs {
					nodeCfgs.Resources.WireGuard.WireGuardConfigs[i].ContainerName = pkgutils.StringPtr(ContainerName)
				}
			}
		}

	}

	yaml.NewEncoder(os.Stdout).Encode(nodeCfgs)
	if err != nil {
		log.Fatalf("failed to encode node configs: %v", err)
	}
}

func init() {
	flag.StringVar(&WGConfsDir, "wg-confsd", "wg", "the directory containing the WireGuard config files")
	flag.StringVar(&ContainerName, "container", "", "the container name")
}
