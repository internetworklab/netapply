package container

import (
	"context"
	"fmt"

	"os"
	"path"
	"strings"

	"github.com/docker/docker/api/types/mount"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgfrrdaemons "github.com/internetworklab/netapply/pkg/frr/daemons"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

func (frrContainerConfig *FRRContainerConfig) Apply(ctx context.Context) error {
	statefulDir := pkgutils.GetStatefulDir(ctx)

	frrConfigDir := path.Join(statefulDir, "frr", "containers", frrContainerConfig.ContainerName)
	err := os.MkdirAll(frrConfigDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create frr config dir: %w", err)
		}
	}

	daemonsFilePath := path.Join(frrConfigDir, "daemons")
	daemonsConfig := frrContainerConfig.Daemons
	if daemonsConfig == nil {
		daemonsConfig = pkgfrrdaemons.DefaultFRRDaemonsConfig()
	}
	daemonsConfigLines, err := daemonsConfig.ToConfigLines(ctx)
	if err != nil {
		return fmt.Errorf("failed to convert daemons config to config lines: %w", err)
	}
	err = os.WriteFile(daemonsFilePath, []byte(strings.Join(daemonsConfigLines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("failed to write daemons file: %w", err)
	}

	serviceName := ""
	if s, err := pkgutils.ServiceNameFromCtx(ctx); err == nil {
		serviceName = s
	}

	containerConfig := &pkgdocker.DockerContainerConfig{
		ContainerName: frrContainerConfig.ContainerName,
		Image:         DefaultImage,
		Capabilities:  []string{"net_admin", "sys_admin"},
		Hostname:      frrContainerConfig.Hostname,
		Volumes: []pkgdocker.DockerMountConfig{
			{
				Type:   mount.TypeBind,
				Source: daemonsFilePath,
				Target: "/etc/frr/daemons",
			},
		},
	}

	if serviceName != "" {
		labels := map[string]string{
			pkgdocker.LabelKeyService: serviceName,
		}
		containerConfig.Labels = labels
	}

	if frrContainerConfig.Image != nil {
		containerConfig.Image = *frrContainerConfig.Image
	}

	return containerConfig.Apply(ctx)
}

func DefaultFRRContainerConfig() *FRRContainerConfig {
	cfg := new(FRRContainerConfig)
	cfg.ContainerName = "frr"
	cfg.Daemons = pkgfrrdaemons.DefaultFRRDaemonsConfig()
	cfg.Image = new(string)
	*cfg.Image = DefaultImage
	cfg.Hostname = new(string)
	*cfg.Hostname = "frr-test-node"
	return cfg
}
