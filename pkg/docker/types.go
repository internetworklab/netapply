package docker

import (
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
)

type DockerMountConfig struct {
	Type   mount.Type `yaml:"type" json:"type"`
	Source string     `yaml:"source" json:"source"`
	Target string     `yaml:"target" json:"target"`
}

type DockerDeviceMapping struct {
	// For example, "/dev/net/tun"
	PathOnHost string `yaml:"path_on_host" json:"path_on_host"`

	// For example, "/dev/net/tun"
	PathInContainer string `yaml:"path_in_container" json:"path_in_container"`

	// Should use "rwm" mostly
	CgroupPermissions *string `yaml:"cgroup_permissions,omitempty" json:"cgroup_permissions,omitempty"`
}

type DockerPortMapping struct {
	HostIP   string `yaml:"host_ip" json:"host_ip"`
	HostPort int    `yaml:"host_port" json:"host_port"`
}

type DockerContainerConfig struct {
	Image         string                         `yaml:"image" json:"image"`
	ContainerName string                         `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Capabilities  []string                       `yaml:"cap_add,omitempty" json:"cap_add,omitempty"`
	Hostname      *string                        `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	Ports         map[string][]DockerPortMapping `yaml:"ports,omitempty" json:"ports,omitempty"`
	Volumes       []DockerMountConfig            `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	Devices       []DockerDeviceMapping          `yaml:"devices,omitempty" json:"devices,omitempty"`
	AutoRemove    *bool                          `yaml:"autoremove,omitempty" json:"autoremove,omitempty"`
	Networks      []string                       `yaml:"networks,omitempty" json:"networks,omitempty"`
	Command       []string                       `yaml:"command,omitempty" json:"command,omitempty"`
	Labels        map[string]string              `yaml:"labels,omitempty" json:"labels,omitempty"`
	TTY           *bool                           `yaml:"tty,omitempty" json:"tty,omitempty"`
	OpenStdin     *bool                           `yaml:"stdin_open,omitempty" json:"stdin_open,omitempty"`
}

type ContainerKey string

const (
	ContainerKeyHost ContainerKey = "-"
)

type ContainerList struct {
	containers []container.Summary
}

type ContainerDockerConfig struct {
	Name string `yaml:"name" json:"name"`
}

type ContainerConfig struct {
	Docker ContainerDockerConfig `yaml:"docker,omitempty" json:"docker,omitempty"`
}
