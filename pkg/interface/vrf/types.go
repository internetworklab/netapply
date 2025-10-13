package vrf

import (
	pkginterfacecommon "github.com/internetworklab/netapply/pkg/interface/common"
)

type VRFConfig struct {
	Name          string                             `yaml:"name" json:"name"`
	ContainerName *string                            `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	TableId       int                                `yaml:"table_id" json:"table_id"`
	Addresses     []pkginterfacecommon.AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type VRFConfigurationList []VRFConfig

const VRFNameEmpty = ""
const VRFNameDefault = "default"

// If the master index of a link is 0, we consider its VRF as default VRF
const DefaultVRFIndex int = 0
