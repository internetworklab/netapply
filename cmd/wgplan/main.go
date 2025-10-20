package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/alecthomas/kong"

	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgwgplan "github.com/internetworklab/netapply/pkg/wgplan"
	"gopkg.in/yaml.v3"
)

type GenerateCmd struct {
	PlanFile      string `required:"" help:"The plan file to use"`
	KeysOutDir    string `help:"The directory to write the keys to" default:"keys"`
	PlaintextKeys bool   `help:"Write the keys in plaintext to to the YAML output" default:"false"`
	NoKeysOutput  bool   `help:"Do not write the private keys to directory"`
}

func getPlan(planFile string) (*pkgwgplan.WGPlan, error) {
	var f *os.File
	var err error

	if planFile == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(planFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open plan file: %w", err)
		}
		defer f.Close()
	}

	plan := new(pkgwgplan.WGPlan)
	if err := yaml.NewDecoder(f).Decode(plan); err != nil {
		return nil, fmt.Errorf("failed to decode plan: %w", err)
	}
	return plan, nil
}

func (c *GenerateCmd) Run() error {
	planFile := c.PlanFile

	plan, err := getPlan(planFile)
	if err != nil {
		return fmt.Errorf("failed to get plan: %w", err)
	}

	if err := plan.Generate(c.PlaintextKeys, c.NoKeysOutput, c.KeysOutDir); err != nil {
		return fmt.Errorf("failed to generate plan: %w", err)
	}

	enc := yaml.NewEncoder(os.Stdout)
	enc.SetIndent(2)
	if err := enc.Encode(plan); err != nil {
		return fmt.Errorf("failed to encode plan: %w", err)
	}

	return nil
}

type PopulateCmd struct {
	PlanFile    string `required:"" help:"The plan file to use"`
	TargetGlobs string `required:"" help:"The target globs to use to search for the targets"`
	BaseDir     string `help:"The base directory to use to search for the targets" default:"."`
	DryRun      bool   `help:"Do not actually populate the plan" default:"false"`
}

func (c *PopulateCmd) Run() error {

	matches, err := filepath.Glob(c.TargetGlobs)
	if err != nil {
		return fmt.Errorf("failed to glob targets: %w", err)
	}

	if c.DryRun {
		for _, match := range matches {
			log.Printf("Found target blob: %s", match)
		}
		return nil
	}

	plan, err := getPlan(c.PlanFile)
	if err != nil {
		return fmt.Errorf("failed to get plan: %w", err)
	}

	if plan.IndexedConnections == nil {
		return fmt.Errorf("plan has no indexed connections, please generate the plan first")
	}

	for _, path := range matches {
		log.Printf("Populating plan with target blob: %s", path)
		f, err := os.Open(path)
		if err != nil {
			log.Printf("failed to open node config, skipping: %v", err)
			continue
		}
		defer f.Close()
		nodeCfg := new(pkgmodels.NodeConfig)
		if err := yaml.NewDecoder(f).Decode(nodeCfg); err != nil {
			log.Printf("failed to decode node config, skipping: %v", err)
			continue
		}
		if nodeCfg.Resources == nil {
			log.Printf("node config has no resources, skipping: %v", path)
			continue
		}
		if nodeCfg.Resources.WireGuard == nil {
			log.Printf("node config has no wireguard resources, skipping: %v", path)
			continue
		}
		updatedWGCfgs := make([]pkginterfacewireguard.WireGuardConfig, 0)
		for _, wgCfg := range nodeCfg.Resources.WireGuard.WireGuardConfigs {
			connID := wgCfg.Additionals[pkginterfacewireguard.WGAdditionalKeyConnectionID]
			if connID == "" {
				continue
			}

			if conn, ok := plan.IndexedConnections[connID]; ok {
				log.Printf("Found connection %s in plan, file: %s", connID, path)
				if conn.SelfPrivateKey != nil {
					wgCfg.PrivateKey = *conn.SelfPrivateKey
				}
				if conn.SelfPrivateKeyFile != nil {
					wgCfg.PrivateKeyFrom = conn.SelfPrivateKeyFile
				}
				peerCfg := &pkginterfacewireguard.WireGuardPeerConfig{}
				peerCfg.PublicKey = conn.PeerPublicKey
				peerCfg.AllowedIPs = []string{
					"0.0.0.0/0",
					"::/0",
				}

				if conn.PeerEndpointHost != nil && conn.PeerEndpointPort != nil {
					ep := net.JoinHostPort(*conn.PeerEndpointHost, strconv.Itoa(*conn.PeerEndpointPort))
					peerCfg.Endpoint = &ep
				}

				wgCfg.Peers = []pkginterfacewireguard.WireGuardPeerConfig{*peerCfg}
				updatedWGCfgs = append(updatedWGCfgs, wgCfg)
			}
		}
		nodeCfg.Resources.WireGuard.WireGuardConfigs = updatedWGCfgs
		if err := yaml.NewEncoder(f).Encode(nodeCfg); err != nil {
			log.Printf("failed to encode node config and save, skipping: %v", err)
			continue
		}
		log.Printf("Config file %s is updated", path)
	}

	return nil
}

type CLI struct {
	Generate GenerateCmd `cmd:"" help:"Generate a WireGuard plan"`
	Populate PopulateCmd `cmd:"" help:"Populate a WireGuard plan with the given keys"`
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)
	err := ctx.Run()
	if err != nil {
		log.Fatalf("Failed to run command: %v", err)
	}
}
