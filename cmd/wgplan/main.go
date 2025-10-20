package main

import (
	"fmt"
	"log"
	"os"

	"github.com/alecthomas/kong"

	pkgwgplan "github.com/internetworklab/netapply/pkg/wgplan"
	"gopkg.in/yaml.v3"
)

type GenerateCmd struct {
	PlanFile      string `required:"" help:"The plan file to use"`
	KeysOutDir    string `help:"The directory to write the keys to" default:"keys"`
	PlaintextKeys bool   `help:"Write the keys in plaintext to to the YAML output" default:"false"`
	NoKeysOutput  bool   `help:"Do not write the private keys to directory"`
}

func (c *GenerateCmd) Run() error {
	planFile := c.PlanFile

	var f *os.File
	var err error

	if planFile == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(planFile)
		if err != nil {
			return fmt.Errorf("failed to open plan file: %w", err)
		}
		defer f.Close()
	}

	plan := new(pkgwgplan.WGPlan)
	if err := yaml.NewDecoder(f).Decode(plan); err != nil {
		return fmt.Errorf("failed to decode plan: %w", err)
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

type CLI struct {
	Generate GenerateCmd `cmd:"" help:"Generate a WireGuard plan"`
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)
	err := ctx.Run()
	if err != nil {
		log.Fatalf("Failed to run command: %v", err)
	}
}
