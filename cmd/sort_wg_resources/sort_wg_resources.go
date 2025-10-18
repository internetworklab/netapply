package main

import (
	"flag"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"

	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	"gopkg.in/yaml.v3"
)

const WGConfigFileExtension = ".conf"
const WGMaskFileExtension = ".mask"

var (
	PathToResourceYAML string
)

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

func main() {
	flag.Parse()
	if PathToResourceYAML == "" {
		log.Fatalf("path-to-resource-yaml is required")
	}

	f, err := os.Open(PathToResourceYAML)
	if err != nil {
		log.Fatalf("failed to open resource YAML file: %v", err)
	}
	defer f.Close()

	nodeCfgs := new(pkgmodels.NodeConfig)

	err = yaml.NewDecoder(f).Decode(nodeCfgs)
	if err != nil {
		log.Fatalf("failed to decode resource YAML file: %v", err)
	}

	if nodeCfgs.Resources != nil {
		if nodeCfgs.Resources.WireGuard != nil {
			wgs := make([]pkginterfacewireguard.WireGuardConfig, 0)
			if nodeCfgs.Resources.WireGuard.WireGuardConfigs != nil {
				wgs = append(wgs, nodeCfgs.Resources.WireGuard.WireGuardConfigs...)
			}
			sort.Slice(wgs, func(i, j int) bool {
				return extractIfIndex(wgs[i].Name) < extractIfIndex(wgs[j].Name)
			})
			nodeCfgs.Resources.WireGuard.WireGuardConfigs = wgs
		}
	}

	yaml.NewEncoder(os.Stdout).Encode(nodeCfgs)
	if err != nil {
		log.Fatalf("failed to encode node configs: %v", err)
	}
}

func init() {
	flag.StringVar(&PathToResourceYAML, "path-to-resource-yaml", "path-to-resource-yaml", "the path to the resource YAML file")
}
