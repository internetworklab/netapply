package container

import "github.com/docker/docker/api/types"

const DefaultVtyshPath = "vtysh"

type ContainerVtyshConfigWriter struct {
	containerName string
	vtyshPath     *string
	dockerIO      *types.HijackedResponse
	execID        string
	contID        string
}
