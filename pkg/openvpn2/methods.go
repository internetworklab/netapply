package openvpn2

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkginterfacestub "github.com/internetworklab/netapply/pkg/interface/stub"
	pkgopenvpnstructtag "github.com/internetworklab/netapply/pkg/openvpn2/structtag"
	pkgreconcile "github.com/internetworklab/netapply/pkg/reconcile"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
	"github.com/vishvananda/netlink"
)

func getFileVolume(ctx context.Context, containerName, hostPath, containerPath, volName string) (*pkgdocker.DockerMountConfig, error) {
	hostPath = strings.TrimSpace(hostPath)
	if hostPath == pkgutils.FilePathPresumedToBeStdin || hostPath == pkgutils.FilePathThatIsStdin {
		return nil, fmt.Errorf("invalid host path: %s", hostPath)
	}

	if strings.HasPrefix(hostPath, "https://") || strings.HasPrefix(hostPath, "http://") {

		clientAuth, err := pkgutils.ClientAuthFromCtx(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get client auth from context: %w", err)
		}

		readerConfig := &pkgutils.URLReaderTransportOptions{
			Username: clientAuth.HTTPBasicAuthUsername,
			Password: clientAuth.HTTPBasicAuthPassword,
		}

		if strings.HasPrefix(hostPath, "https://") {
			readerConfig.TLSConfig, err = pkgutils.GetTLSConfig(clientAuth.TLSTrustedCACertFile, clientAuth.TLSClientCertFile, clientAuth.TLSClientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to get TLS config: %w", err)
			}
		}

		reader, err := pkgutils.NewURLReader(hostPath, readerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create URL reader: %w", err)
		}
		defer reader.Close()

		stateDir := pkgutils.GetStatefulDir(ctx)
		actualHostPath := path.Join(stateDir, "openvpn", "containers", containerName, "tmpvols", volName)
		err = os.MkdirAll(path.Dir(actualHostPath), 0755)
		if err != nil {
			if !os.IsExist(err) {
				return nil, fmt.Errorf("failed to create actual host file dir: %w", err)
			}
		}
		actualHostFile, err := os.OpenFile(actualHostPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)

		if err != nil {
			return nil, fmt.Errorf("failed to open actual host file: %w", err)
		}
		defer actualHostFile.Close()
		_, err = io.Copy(actualHostFile, reader)
		if err != nil {
			return nil, fmt.Errorf("failed to copy file: %w", err)
		}

		return &pkgdocker.DockerMountConfig{
			Type:   mount.TypeBind,
			Source: actualHostPath,
			Target: containerPath,
		}, nil
	}

	return &pkgdocker.DockerMountConfig{
		Type:   mount.TypeBind,
		Source: hostPath,
		Target: containerPath,
	}, nil
}

func getCertVolumes(ctx context.Context, ovpInst *OpenVPN2Instance) ([]pkgdocker.DockerMountConfig, error) {
	volumes := make([]pkgdocker.DockerMountConfig, 0)
	certVol, err := getFileVolume(ctx, ovpInst.Name, ovpInst.HostTLSCertFile, "/etc/openvpn/certs/cert.pem", "openvpnclientcert.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to get cert volume: %w", err)
	}
	volumes = append(volumes, *certVol)
	keyVol, err := getFileVolume(ctx, ovpInst.Name, ovpInst.HostTLSKeyFile, "/etc/openvpn/certs/key.pem", "openvpnclientkey.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to get key volume: %w", err)
	}
	volumes = append(volumes, *keyVol)

	if ovpInst.DHPEMFile != nil {
		dhVol, err := getFileVolume(ctx, ovpInst.Name, *ovpInst.HostDHPEMFile, "/etc/openvpn/certs/dh.pem", "openvpnclientdh.pem")
		if err != nil {
			return nil, fmt.Errorf("failed to get dh volume: %w", err)
		}
		volumes = append(volumes, *dhVol)
	}

	return volumes, nil
}

func (ovp *OpenVPN2RemoteTLSCertType) ToCLIArgs() ([]string, error) {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%v", *ovp))
	}
	return res, nil
}

func (ovp *OpenVPN2KeepaliveConfig) ToCLIArgs() ([]string, error) {

	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%d", ovp.IntervalSecs))
		res = append(res, fmt.Sprintf("%d", ovp.PatienceSecs))
	}
	return res, nil
}

func (ovp *OpenVPN2RemoteConfig) ToCLIArgs() ([]string, error) {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, ovp.Host)
		res = append(res, fmt.Sprintf("%d", ovp.Port))
		if ovp.Proto != nil && *ovp.Proto != "" {
			res = append(res, *ovp.Proto)
		}
	}
	return res, nil
}

func (ovpInst *OpenVPN2Instance) DetectChanges(ctx context.Context) (pkgreconcile.InterfaceChangeSet, error) {
	return nil, nil
}

func (ovpInst *OpenVPN2Instance) GetContainerName() *string {
	return &ovpInst.Name
}

func (ovpInst *OpenVPN2Instance) GetInterfaceName() string {
	return ovpInst.Dev
}

func (ovpInst *OpenVPN2Instance) Update(ctx context.Context) error {
	return nil
}

const labelCategoryDataplane string = "dataplane"
const labelIfaceTypeOpenVPN string = "openvpn"

func (ovpInst *OpenVPN2Instance) GetType() string {
	return new(netlink.Tuntap).Type()
}

func (ovpInst *OpenVPN2Instance) CheckExist(ctx context.Context) (bool, error) {
	return pkginterfacestub.CheckExist(ctx, ovpInst)
}

func (ovpInst *OpenVPN2Instance) Create(ctx context.Context) error {
	servicename, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		// servicename is needed, otherwise the controller won't be able
		// to do the cleanup job later.
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	openvpnExec := "openvpn"
	if ovpInst.ExecutablePath != nil && *ovpInst.ExecutablePath != "" {
		openvpnExec = *ovpInst.ExecutablePath
	}

	cmd := make([]string, 0)
	cmd = append(cmd, openvpnExec)
	cliargs, err := pkgopenvpnstructtag.Marshal(ovpInst)
	if err != nil {
		return fmt.Errorf("failed to marshal openvpn2 instance into CLI arguments: %w", err)
	}
	cmd = append(cmd, cliargs...)

	devPermRWM := "rwm"
	containerConfig := pkgdocker.DockerContainerConfig{
		ContainerName: ovpInst.Name,
		Hostname:      ovpInst.HostName,
		Labels: map[string]string{
			pkgdocker.LabelKeyService:   servicename,
			pkgdocker.LabelKeyInstance:  ovpInst.Name,
			pkgdocker.LabelKeyCategory:  labelCategoryDataplane,
			pkgdocker.LabelKeyIfaceType: labelIfaceTypeOpenVPN,
		},
		Command:    cmd,
		TTY:        ovpInst.TTY,
		OpenStdin:  ovpInst.OpenStdin,
		AutoRemove: ovpInst.AutoRemove,
		Networks:   ovpInst.DockerNetworks,
		Image:      ovpInst.Image,
		Capabilities: []string{
			"net_admin",
			"sys_admin",
		},
		Ports: ovpInst.Ports,
		Devices: []pkgdocker.DockerDeviceMapping{
			{
				PathOnHost:        "/dev/net/tun",
				PathInContainer:   "/dev/net/tun",
				CgroupPermissions: &devPermRWM,
			},
		},
	}
	stateDir := pkgutils.GetStatefulDir(ctx)
	ovpConfigDir := path.Join(stateDir, "openvpn", "containers", ovpInst.Name)
	err = os.MkdirAll(ovpConfigDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create openvpn config dir: %w", err)
		}
	}
	ovpScriptDir := path.Join(ovpConfigDir, "scripts")
	err = os.MkdirAll(ovpScriptDir, 0755)
	if err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create openvpn script dir: %w", err)
		}
	}
	upWrapperScriptPath := path.Join(ovpScriptDir, "up-wrapper.sh")

	scriptContent := []byte(strings.Join([]string{
		"#!/bin/bash",
		"",
		"echo \"Setting up $1\"",
		"ip link set $1 up",
		"",
	}, "\n"))

	// Repetitive write will simply override the previous content,
	// so nothing to worry about.
	if err := os.WriteFile(upWrapperScriptPath, scriptContent, 0755); err != nil {
		return fmt.Errorf("failed to write up-wrapper script: %w", err)
	}

	volumes := []pkgdocker.DockerMountConfig{
		{
			Type:   mount.TypeBind,
			Source: pkgutils.ResolvePath(upWrapperScriptPath),
			Target: "/up-wrapper.sh",
		},
	}

	certVols, err := getCertVolumes(ctx, ovpInst)
	if err != nil {
		return fmt.Errorf("failed to get TLS volumes: %w", err)
	}
	volumes = append(volumes, certVols...)

	containerConfig.Volumes = volumes
	return containerConfig.Apply(ctx)
}

func (ovpInst *OpenVPN2Instance) IsLinkExists(ctx context.Context) bool {
	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		panic(err)
	}

	cont, err := pkgdocker.FindContainer(ctx, cli, ovpInst.Name)
	if err != nil {
		return false
	}

	if cont == nil {
		return false
	}

	return true
}

// By default, it scans all tun/tap virtual interfaces in the specified containers
func getContainerAndIfaces(ctx context.Context, serviceName string, containerNames []string) (map[string]map[string]pkgreconcile.ResourceCanceller, error) {
	args := filters.NewArgs()
	args.Add("label", fmt.Sprintf("%s=%s", pkgdocker.LabelKeyService, serviceName))
	args.Add("label", fmt.Sprintf("%s=%s", pkgdocker.LabelKeyCategory, labelCategoryDataplane))
	args.Add("label", fmt.Sprintf("%s=%s", pkgdocker.LabelKeyIfaceType, labelIfaceTypeOpenVPN))

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	conts, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: args,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	scanContNameSet := make(map[string]bool)
	for _, contName := range containerNames {
		scanContNameSet[contName] = true
	}

	result := make(map[string]map[string]pkgreconcile.ResourceCanceller)
	for _, cont := range conts {
		contName := pkgutils.NormalizeContainerName(cont.Names[0])

		if !pkgdocker.IsRegularContainerName(contName) {
			// This would be very likely to be the host netns, skip it
			continue
		}

		if _, ok := scanContNameSet[contName]; !ok {
			// This doesn't seems like any one of the containers we're interested in, skip it
			continue
		}

		ifaceMap, err := pkgreconcile.GetInterfaceFromContainer(ctx, &contName, "tuntap")
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from container: %w", err)
		}
		result[contName] = ifaceMap
	}

	// here's how to rewrap:
	// 1. If the netns is host, the canceller simply does nothing,
	//    it won't ever try do delete anything in the host netns,
	//    because all the openvpn instances are supposed to be provisioned
	//    in the container's form but never in host netns, so, if there's
	//    anything in the host netns that looks like an openvpn tuntap interface,
	//    it's definitely not created by us.
	//    (of course, this is guaranteed because we already skipped the host netns, see Line 313)
	//
	// 2. All openvpn2-related containers are deleted in its entirety,
	//    when the canceller performs its cancellation job, the entire container
	//    will be deleted along with all its interfaces all at once.
	return rewrapOpenVPN2InstanceCancellers(ctx, result), nil
}

func (ovpCfgsList OpenVPN2ConfigurationList) GetProvisioners() []pkgreconcile.ResourceProvisioner {
	provisioners := make([]pkgreconcile.ResourceProvisioner, 0)
	for _, ovpCfg := range ovpCfgsList.Instances {
		provisioners = append(provisioners, &ovpCfg)
	}
	return provisioners
}

// Wrap all cancellers in one netns into a single canceller that cancels the entire container (hence all interfaces in it are also cancelled alongside)
func rewrapOpenVPN2InstanceCancellers(ctx context.Context, cancellersMap map[string]map[string]pkgreconcile.ResourceCanceller) map[string]map[string]pkgreconcile.ResourceCanceller {
	rewrappedCancellersMap := make(map[string]map[string]pkgreconcile.ResourceCanceller)
	for nsKey, ifaceMap := range cancellersMap {
		if len(ifaceMap) == 0 {
			continue
		}
		for _, canceller := range ifaceMap {
			containerName := canceller.GetContainerName()
			if containerName == nil {
				continue
			}
			if !pkgdocker.IsRegularContainerName(*containerName) {
				// like said, we try best not to delete anything in the host netns.
				continue
			}
			interfaceName := canceller.GetInterfaceName()
			ovp2Canceller := &OpenVPN2InterfaceCanceller{
				ContainerName: *containerName,
				InterfaceName: interfaceName,
			}
			if _, ok := rewrappedCancellersMap[nsKey]; !ok {
				rewrappedCancellersMap[nsKey] = make(map[string]pkgreconcile.ResourceCanceller)
			}
			rewrappedCancellersMap[nsKey][interfaceName] = ovp2Canceller

			// one canceller per one container(netns), so, no more loops needed
			break
		}
	}
	return rewrappedCancellersMap
}

func (ovpCfgsList OpenVPN2ConfigurationList) IndexCurrentResources(ctx context.Context) (map[string]map[string]pkgreconcile.ResourceCanceller, error) {
	servicename, err := pkgutils.ServiceNameFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get service name from context: %w", err)
	}

	cancellersMap, err := getContainerAndIfaces(ctx, servicename, ovpCfgsList.Containers)
	if err != nil {
		return nil, fmt.Errorf("failed to get container and interfaces: %w", err)
	}

	return cancellersMap, nil
}

func (ovpCfgsList OpenVPN2ConfigurationList) GetContainers() []string {
	return ovpCfgsList.Containers
}

func (ovpCfgsList OpenVPN2ConfigurationList) GetType() string {
	return new(netlink.Tuntap).Type()
}

func (ovpCfgsList OpenVPN2ConfigurationList) CheckResourceExistInSpec(ctx context.Context, specsMap map[string]map[string]pkgreconcile.ResourceProvisioner, resource pkgreconcile.ResourceCanceller) (bool, error) {
	return pkgreconcile.CheckResourceExistInSpec(ctx, specsMap, resource)
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) Cancel(ctx context.Context) error {
	return pkgdocker.StopAndRemoveContainer(ctx, ovpInterfaceCanceller.ContainerName)
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetContainerName() *string {
	return &ovpInterfaceCanceller.ContainerName
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetInterfaceName() string {
	return ovpInterfaceCanceller.InterfaceName
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetType() string {
	return new(netlink.Tuntap).Type()
}
