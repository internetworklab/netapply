package main

import (
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	pkginterfacevrf "github.com/internetworklab/netapply/pkg/interface/vrf"
	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"gopkg.in/yaml.v3"
)

const WGConfigFileExtension = ".conf"
const WGMaskFileExtension = ".mask"

func extractIfIndex(ifname string) int {
	re := regexp.MustCompile(`^utun(\d+)$`)
	matches := re.FindStringSubmatch(ifname)
	if len(matches) == 0 {
		// if it's not found, return -1
		return -1
	}
	n, err := strconv.Atoi(matches[1])
	if err != nil {
		return -1
	}

	return n
}

var (
	ContainerName string
	WGConfsDir    string
	VRF           string
	VRFTableId    int
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

	if nodeCfgs.Resources != nil {
		if nodeCfgs.Resources.WireGuard != nil {
			if ContainerName != "" {
				nodeCfgs.Resources.WireGuard.Containers = []string{ContainerName}
				for i := range nodeCfgs.Resources.WireGuard.WireGuardConfigs {
					nodeCfgs.Resources.WireGuard.WireGuardConfigs[i].ContainerName = pkgutils.StringPtr(ContainerName)
				}
			}

			if VRF != "" && VRFTableId != 0 {
				for i := range nodeCfgs.Resources.WireGuard.WireGuardConfigs {
					nodeCfgs.Resources.WireGuard.WireGuardConfigs[i].VRF = pkgutils.StringPtr(VRF)
				}

				nodeCfgs.Resources.VRF = new(pkginterfacevrf.VRFConfigurationList)
				if ContainerName != "" {
					nodeCfgs.Resources.VRF.Containers = []string{}
				}
				vrfs := make([]pkginterfacevrf.VRFConfig, 0)
				vrf := pkginterfacevrf.VRFConfig{
					Name:    VRF,
					TableId: uint32(VRFTableId),
				}
				if ContainerName != "" {
					vrf.ContainerName = pkgutils.StringPtr(ContainerName)
				}
				vrfs = append(vrfs, vrf)
				nodeCfgs.Resources.VRF.VRFs = vrfs
			}

			// always sort, regardless what
			wgcfgs := nodeCfgs.Resources.WireGuard.WireGuardConfigs
			sort.Slice(wgcfgs, func(i, j int) bool {
				return extractIfIndex(wgcfgs[i].Name) < extractIfIndex(wgcfgs[j].Name)
			})
			nodeCfgs.Resources.WireGuard.WireGuardConfigs = wgcfgs
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
	flag.StringVar(&VRF, "vrf", "", "the VRF name")
	flag.IntVar(&VRFTableId, "vrf-table-id", 0, "the VRF table id")
}
