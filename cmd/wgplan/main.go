package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"github.com/alecthomas/kong"

	pkginterfacewireguard "github.com/internetworklab/netapply/pkg/interface/wireguard"
	pkgmodels "github.com/internetworklab/netapply/pkg/models"
	pkgwgplan "github.com/internetworklab/netapply/pkg/wgplan"
	"gopkg.in/yaml.v3"
)

type GenerateCmd struct {
	PlanFile       string `required:"" help:"The plan file to use"`
	KeysOutDir     string `help:"The directory to write the keys to" default:"keys"`
	PlaintextKeys  bool   `help:"Write the keys in plaintext to to the YAML output" default:"false"`
	NoKeysOutput   bool   `help:"Do not write the private keys to directory"`
	NoPlanOutput   bool   `help:"Do not write the plan to output" default:"false"`
	WgConfsOutFile string `help:"The file to write the WireGuard configs to" default:""`
}

const useIndent = 2

func getPlanInput(planFile string) (*pkgwgplan.WGPlan, error) {
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

	plan, err := getPlanInput(planFile)
	if err != nil {
		return fmt.Errorf("failed to get plan: %w", err)
	}

	privkeys, err := plan.Generate(c.PlaintextKeys)
	if err != nil {
		return fmt.Errorf("failed to generate plan: %w", err)
	}

	if !c.NoKeysOutput {
		os.MkdirAll(c.KeysOutDir, 0755)
		for connID, privkey := range privkeys {
			fileName := fmt.Sprintf("%s.key", connID)
			filePath := path.Join(c.KeysOutDir, fileName)
			if err := os.WriteFile(filePath, []byte(privkey), 0644); err != nil {
				return fmt.Errorf("failed to write key file %s: %w", filePath, err)
			}
			if conn, ok := plan.IndexedConnections[connID]; ok {
				conn.SelfPrivateKeyFile = &filePath
			}
		}
	}

	if !c.NoPlanOutput {
		enc := yaml.NewEncoder(os.Stdout)
		enc.SetIndent(useIndent)
		if err := enc.Encode(plan); err != nil {
			return fmt.Errorf("failed to encode plan: %w", err)
		}
	}

	if c.WgConfsOutFile != "" {
		var f *os.File
		var err error
		f, err = os.Create(c.WgConfsOutFile)
		if err != nil {
			return fmt.Errorf("failed to create WireGuard configs output file for writing: %w", err)
		}
		defer f.Close()
		wgConfs, err := plan.ToWgConfs(privkeys)
		if err != nil {
			return fmt.Errorf("failed to convert plan to WireGuard configs: %w", err)
		}
		enc := yaml.NewEncoder(f)
		enc.SetIndent(useIndent)
		if err := enc.Encode(wgConfs); err != nil {
			return fmt.Errorf("failed to encode WireGuard configs to file: %w", err)
		}
	}

	return nil
}

type PopulateCmd struct {
	PlanFile    string `required:"" help:"The plan file to use"`
	TargetGlobs string `required:"" help:"The target globs to use to search for the targets"`
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

	plan, err := getPlanInput(c.PlanFile)
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
				log.Printf("Populated connection %s in file: %s", connID, path)
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
