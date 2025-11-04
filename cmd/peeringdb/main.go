package main

import (
	"log"
	"os"

	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v3"

	pkgbird "github.com/internetworklab/netapply/pkg/bird"
)

var CLI struct {
	FromDirectory string `help:"Directory to read from." type:"path"`
	FromYAML      string `help:"YAML file to read from." type:"path"`
	ToDirectory   string `help:"Directory to write to." type:"path"`
}

func main() {
	kong.Parse(&CLI)
	var protoList pkgbird.BGPProtoList
	var err error
	if CLI.FromDirectory != "" {
		protoList, err = pkgbird.FromDirectory(CLI.FromDirectory)
		if err != nil {
			log.Fatalf("failed to read from directory %s: %v", CLI.FromDirectory, err)
		}
	} else if CLI.FromYAML != "" {
		f, err := os.Open(CLI.FromYAML)
		if err != nil {
			log.Fatalf("failed to open YAML file %s: %v", CLI.FromYAML, err)
		}
		defer f.Close()
		yaml.NewDecoder(f).Decode(&protoList)
	}

	if CLI.ToDirectory != "" {
		if CLI.ToDirectory != "" {
			err = protoList.ToConfigs(CLI.ToDirectory)
			if err != nil {
				log.Fatalf("failed to write to directory %s: %v", CLI.ToDirectory, err)
			}
		}
	} else {
		encoder := yaml.NewEncoder(os.Stdout)
		encoder.SetIndent(2)
		err = encoder.Encode(protoList)
		if err != nil {
			log.Fatalf("failed to encode YAML: %v", err)
		}
	}
}
