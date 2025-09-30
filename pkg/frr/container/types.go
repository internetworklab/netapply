package container

import (
	pkgfrrdaemons "example.com/connector/pkg/frr/daemons"
)

type FRRContainerConfig struct {
	ContainerName string                          `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Daemons       *pkgfrrdaemons.FRRDaemonsConfig `yaml:"daemons,omitempty" json:"daemons,omitempty"`
	Image         *string                         `yaml:"image,omitempty" json:"image,omitempty"`
	Hostname      *string                         `yaml:"hostname,omitempty" json:"hostname,omitempty"`
}

const DefaultImage = "quay.io/frrouting/frr:10.3.0"
