package container

import (
	pkgfrrdaemons "github.com/internetworklab/netapply/pkg/frr/daemons"
)

type FRRContainerConfig struct {
	ContainerName string                          `yaml:"container_name" json:"container_name"`
	Daemons       *pkgfrrdaemons.FRRDaemonsConfig `yaml:"daemons,omitempty" json:"daemons,omitempty"`
	Image         *string                         `yaml:"image,omitempty" json:"image,omitempty"`
	Hostname      *string                         `yaml:"hostname,omitempty" json:"hostname,omitempty"`
}

const DefaultImage = "quay.io/frrouting/frr:10.3.0"
