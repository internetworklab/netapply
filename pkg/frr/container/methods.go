package container

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	pkgdocker "example.com/connector/pkg/docker"
	pkgutils "example.com/connector/pkg/utils"
	"github.com/docker/docker/api/types/mount"
)

func (frrContainerConfig *FRRContainerConfig) Apply(ctx context.Context) error {
	statefulDir, err := pkgutils.StatefulDirFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get stateful dir from context: %w", err)
	}

	frrConfigDir := path.Join(statefulDir, "frr")
	err = os.MkdirAll(frrConfigDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create frr config dir: %w", err)
		}
	}

	daemonsFilePath := path.Join(frrConfigDir, "daemons")
	daemonsConfigLines, err := frrContainerConfig.Daemons.ToConfigLines(ctx)
	if err != nil {
		return fmt.Errorf("failed to convert daemons config to config lines: %w", err)
	}
	err = os.WriteFile(daemonsFilePath, []byte(strings.Join(daemonsConfigLines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("failed to write daemons file: %w", err)
	}

	serviceName, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	containerConfig := &pkgdocker.DockerContainerConfig{
		ContainerName: frrContainerConfig.ContainerName,
		Image:         DefaultImage,
		Capabilities:  []string{"net_admin", "sys_admin"},
		Hostname:      frrContainerConfig.Hostname,
		Volumes: []pkgdocker.DockerMountConfig{
			{
				Type:   mount.TypeVolume,
				Source: daemonsFilePath,
				Target: "/etc/frr/daemons",
			},
		},
		Labels: map[string]string{
			pkgdocker.LabelKeyService: serviceName,
		},
	}

	if frrContainerConfig.Image != nil {
		containerConfig.Image = *frrContainerConfig.Image
	}

	return containerConfig.Apply(ctx)
}
