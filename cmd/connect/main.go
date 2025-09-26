package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

type OpenVPN2Role string

const (
	OpenVPN2RoleClient OpenVPN2Role = "client"
	OpenVPN2RoleServer OpenVPN2Role = "server"
)

type OpenVPN2Proto string

func (ovp *OpenVPN2Proto) ToCLIArgs() []string {
	if ovp == nil {
		return nil
	}

	res := make([]string, 0)

	x := string(*ovp)
	if x != "" {
		res = append(res, x)
	}

	return res
}

const (
	OpenVPN2ProtoTCP       OpenVPN2Proto = "tcp"
	OpenVPN2ProtoUDP       OpenVPN2Proto = "udp"
	OpenVPN2ProtoTCPServer OpenVPN2Proto = "tcp-server"
	OpenVPN2ProtoUDPServer OpenVPN2Proto = "udp-server"
	OpenVPN2ProtoTCPClient OpenVPN2Proto = "tcp-client"
	OpenVPN2ProtoUDPClient OpenVPN2Proto = "udp-client"
)

type OpenVPN2Topology string

func (ovp *OpenVPN2Topology) ToCLIArgs() []string {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%v", *ovp))
	}
	return res
}

const (
	OpenVPN2TopologySubnet OpenVPN2Topology = "subnet"
	OpenVPN2TopologyNet30  OpenVPN2Topology = "net30"
)

type OpenVPN2KeepaliveConfig struct {
	IntervalSecs int `json:"interval_secs" yaml:"interval_secs"`
	PatienceSecs int `json:"patience_secs" yaml:"patience_secs"`
}

func (ovp *OpenVPN2KeepaliveConfig) ToCLIArgs() []string {

	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%d", ovp.IntervalSecs))
		res = append(res, fmt.Sprintf("%d", ovp.PatienceSecs))
	}
	return res
}

type OpenVPN2RemoteConfig struct {
	Host string `json:"host" yaml:"host"`
	Port int    `json:"port" yaml:"port"`
}

func (ovp *OpenVPN2RemoteConfig) ToCLIArgs() []string {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, ovp.Host)
		res = append(res, fmt.Sprintf("%d", ovp.Port))
	}
	return res
}

type OpenVPN2RemoteTLSCertType string

const (
	OpenVPN2RemoteTLSCertTypeServer OpenVPN2RemoteTLSCertType = "server"
	OpenVPN2RemoteTLSCertTypeClient OpenVPN2RemoteTLSCertType = "client"
)

func (ovp *OpenVPN2RemoteTLSCertType) ToCLIArgs() []string {
	res := make([]string, 0)
	if ovp != nil {
		res = append(res, fmt.Sprintf("%v", *ovp))
	}
	return res
}

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
}

func (dockerConfig *DockerContainerConfig) Create(ctx context.Context) error {
	containerConfig := &container.Config{}
	hostConfig := &container.HostConfig{}
	networkConfig := &network.NetworkingConfig{}
	containerName := dockerConfig.ContainerName
	if containerName == "" {
		return fmt.Errorf("container name is not set")
	}

	dockerConfig.ApplyToContainerCreateConfig(containerConfig, hostConfig, networkConfig)
	containerConfig.Cmd = dockerConfig.Command
	containerConfig.Tty = true
	containerConfig.OpenStdin = true
	servicename, err := serviceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}
	containerConfig.Labels = map[string]string{
		labelKeyService: servicename,
	}

	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	resp, err := cli.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		networkConfig,
		nil,
		containerName,
	)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

func (dockerConfig *DockerContainerConfig) ApplyToContainerCreateConfig(
	containerConfig *container.Config,
	hostConfig *container.HostConfig,
	networkConfig *network.NetworkingConfig,
) {
	if containerConfig != nil {
		containerConfig.Image = dockerConfig.Image
		containerConfig.Cmd = dockerConfig.Command

		if dockerConfig.Hostname != nil {
			containerConfig.Hostname = *dockerConfig.Hostname
		}
	}

	if networkConfig != nil {
		if dockerConfig.Networks != nil {
			networkConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)
			for _, networkName := range dockerConfig.Networks {
				networkConfig.EndpointsConfig[networkName] = &network.EndpointSettings{}
			}
		}
	}

	if hostConfig != nil {
		if dockerConfig.AutoRemove != nil {
			hostConfig.AutoRemove = *dockerConfig.AutoRemove
		}

		if dockerConfig.Capabilities != nil {
			hostConfig.CapAdd = strslice.StrSlice(dockerConfig.Capabilities)
		}

		if dockerConfig.Ports != nil {
			portMaps := make(nat.PortMap, 0)
			for containerPort, hostPortMappings := range dockerConfig.Ports {
				portbindings := make([]nat.PortBinding, 0)
				for _, hostPortMapping := range hostPortMappings {
					portbindings = append(portbindings, nat.PortBinding{
						HostIP:   hostPortMapping.HostIP,
						HostPort: fmt.Sprintf("%d", hostPortMapping.HostPort),
					})
				}
				portMaps[nat.Port(containerPort)] = portbindings
			}
			hostConfig.PortBindings = portMaps
		}

		if dockerConfig.Volumes != nil {
			volumeMounts := make([]mount.Mount, 0)
			for _, volumeMount := range dockerConfig.Volumes {
				volumeMounts = append(volumeMounts, mount.Mount{
					Type:   volumeMount.Type,
					Source: resolvePath(volumeMount.Source),
					Target: volumeMount.Target,
				})
			}
			hostConfig.Mounts = volumeMounts
		}

		if dockerConfig.Devices != nil {
			deviceMounts := make([]container.DeviceMapping, 0)
			for _, deviceMount := range dockerConfig.Devices {
				perm := "rwm"
				if deviceMount.CgroupPermissions != nil {
					perm = *deviceMount.CgroupPermissions
				}
				deviceMounts = append(deviceMounts, container.DeviceMapping{
					PathOnHost:        resolvePath(deviceMount.PathOnHost),
					PathInContainer:   deviceMount.PathInContainer,
					CgroupPermissions: perm,
				})
			}
			hostConfig.Devices = deviceMounts
		}
	}
}

type OpenVPN2Instance struct {
	Name                string                     `openvpn2:"-" yaml:"name"`
	Client              *bool                      `openvpn2:"client" yaml:"client,omitempty"`
	Server              *bool                      `openvpn2:"server" yaml:"server,omitempty"`
	Port                *int                       `openvpn2:"port" yaml:"port,omitempty"`
	Dev                 string                     `openvpn2:"dev" yaml:"dev"`
	Proto               OpenVPN2Proto              `openvpn2:"proto" yaml:"proto"`
	Remote              *OpenVPN2RemoteConfig      `openvpn2:"remote" yaml:"remote,omitempty"`
	NoBind              *bool                      `openvpn2:"no-bind" yaml:"no_bind,omitempty"`
	PersistTun          *bool                      `openvpn2:"persist-tun" yaml:"persist_tun,omitempty"`
	HttpProxy           *OpenVPN2RemoteConfig      `openvpn2:"http-proxy" yaml:"http_proxy,omitempty"`
	CertFile            string                     `openvpn2:"cert" yaml:"cert_file"`
	KeyFile             string                     `openvpn2:"key" yaml:"key_file"`
	DHPEMFile           *string                    `openvpn2:"dh" yaml:"dh,omitempty"`
	PeerFingerprint     string                     `openvpn2:"peer-fingerprint" yaml:"peer_fingerprint"`
	RemoteCertTls       *OpenVPN2RemoteTLSCertType `openvpn2:"remote-cert-tls" yaml:"remote_cert_tls,omitempty"`
	Verb                *int                       `openvpn2:"verb" yaml:"verb,omitempty"`
	TLSServer           *bool                      `openvpn2:"tls-server" yaml:"tls_server,omitempty"`
	DataCiphers         *string                    `openvpn2:"data-ciphers" yaml:"data_ciphers,omitempty"`
	Topology            *OpenVPN2Topology          `openvpn2:"topology" yaml:"topology,omitempty"`
	ServerBridge        *bool                      `openvpn2:"server-bridge" yaml:"server_bridge,omitempty"`
	ClientToClient      *bool                      `openvpn2:"client-to-client" yaml:"client_to_client,omitempty"`
	KeepaliveIntvSecs   *OpenVPN2KeepaliveConfig   `openvpn2:"keepalive" yaml:"keepalive,omitempty"`
	StatusFile          *string                    `openvpn2:"status" yaml:"status_file,omitempty"`
	ExplicitExitNotify  *bool                      `openvpn2:"explicit-exit-notify" yaml:"explicit_exit_notify,omitempty"`
	UpCMD               *string                    `openvpn2:"up" yaml:"up_cmd,omitempty"`
	ScriptSecurityLevel *int                       `openvpn2:"script-security" yaml:"script_security_level,omitempty"`
	ResolvRetry         *string                    `openvpn2:"resolv-retry" yaml:"resolv_retry,omitempty"`
	LLAddr              *string                    `openvpn2:"lladdr" yaml:"lladdr,omitempty"`
	DockerContainer     *DockerContainerConfig     `openvpn2:"-" yaml:"docker_container,omitempty"`
	ExecutablePath      *string                    `openvpn2:"-" yaml:"executable_path,omitempty" json:"executable_path,omitempty"`
}

func (ovpInst *OpenVPN2Instance) DetectChanges(ctx context.Context) (InterfaceChangeSet, error) {
	return nil, nil
}

func (ovpInst *OpenVPN2Instance) GetContainerName() *string {
	return &ovpInst.DockerContainer.ContainerName
}

func (ovpInst *OpenVPN2Instance) GetInterfaceName() string {
	return ovpInst.Dev
}

func (ovpInst *OpenVPN2Instance) Update(ctx context.Context) error {
	return nil
}

type CtxKey string

const ctxKeyDockerCli CtxKey = "docker_cli"
const ctxKeyServiceName CtxKey = "service_name"

func dockerCliFromCtx(ctx context.Context) (*client.Client, error) {
	cli, ok := ctx.Value(ctxKeyDockerCli).(*client.Client)
	if !ok {
		return nil, fmt.Errorf("docker cli is not set in context")
	}

	return cli, nil
}

func serviceNameFromCtx(ctx context.Context) (string, error) {
	serviceName, ok := ctx.Value(ctxKeyServiceName).(string)
	if !ok {
		return "", fmt.Errorf("service name is not set in context")
	}
	return serviceName, nil
}

func setDockerCliInCtx(ctx context.Context, cli *client.Client) context.Context {
	return context.WithValue(ctx, ctxKeyDockerCli, cli)
}

func setServiceNameInCtx(ctx context.Context, serviceName string) context.Context {
	return context.WithValue(ctx, ctxKeyServiceName, serviceName)
}

func getContainerName(service string, instance string) string {
	return fmt.Sprintf("%s-%s", service, instance)
}

func resolvePath(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}

	wd, err := os.Getwd()
	if err != nil {
		return path
	}

	return filepath.Join(wd, path)
}

func (ovpInst *OpenVPN2Instance) Create(ctx context.Context) error {
	servicename, err := serviceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	if ovpInst.DockerContainer == nil {
		return fmt.Errorf("docker container config is not set, currently only support to run in docker container")
	}

	cmd := make([]string, 0)
	exec := "openvpn"
	if ovpInst.ExecutablePath != nil && *ovpInst.ExecutablePath != "" {
		exec = *ovpInst.ExecutablePath
	}
	cmd = append(cmd, exec)
	cmd = append(cmd, ovpInst.ToCLIArgs()...)

	containerConfig := &container.Config{}
	networkConfig := &network.NetworkingConfig{}
	hostConfig := &container.HostConfig{}

	ovpInst.DockerContainer.ApplyToContainerCreateConfig(containerConfig, hostConfig, networkConfig)
	containerConfig.Cmd = cmd
	containerConfig.Tty = true
	containerConfig.OpenStdin = true
	containerConfig.Labels = map[string]string{
		labelKeyService:  servicename,
		labelKeyInstance: ovpInst.Name,
	}

	containerName := ovpInst.DockerContainer.ContainerName
	if containerName == "" {
		containerName = getContainerName(servicename, ovpInst.Name)
	}

	resp, err := cli.ContainerCreate(
		ctx,
		containerConfig,
		hostConfig,
		networkConfig,
		nil,
		containerName,
	)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	return nil
}

func (ovpInst *OpenVPN2Instance) IsLinkExists(ctx context.Context) bool {
	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		panic(err)
	}

	cont, err := findContainer(ctx, cli, ovpInst.DockerContainer.ContainerName)
	if err != nil {
		return false
	}

	if cont == nil {
		return false
	}

	return true
}

const (
	OVTagFlagEmptyKey string = "emptykey"
)

type OSPFInterfaceConfig struct {
	Name    string  `yaml:"name" json:"name"`
	Area    string  `yaml:"area" json:"area"`
	Passive *bool   `yaml:"passive" json:"passive"`
	Network *string `yaml:"network" json:"network"`
}

func (interfaceConfig *OSPFInterfaceConfig) ToCLICommands(ospfConfig *OSPFConfig) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("interface %s vrf %s", interfaceConfig.Name, ospfConfig.VRF))

	cmds = append(cmds, fmt.Sprintf("ip ospf area %s", interfaceConfig.Area))

	if interfaceConfig.Passive != nil && *interfaceConfig.Passive {
		cmds = append(cmds, "ip ospf passive")
	} else if interfaceConfig.Network != nil {
		cmds = append(cmds, fmt.Sprintf("ip ospf network %s", *interfaceConfig.Network))
	}

	cmds = append(cmds, "exit")

	return cmds
}

type OSPFConfig struct {
	// Currently only 'default' vrf is supported
	VRF        string                `yaml:"vrf" json:"vrf"`
	RouterID   string                `yaml:"router_id" json:"router_id"`
	Interfaces []OSPFInterfaceConfig `yaml:"interfaces" json:"interfaces"`
}

func (ospfConf *OSPFConfig) ToCLICommands() []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("router ospf vrf %s", ospfConf.VRF))
	cmds = append(cmds, fmt.Sprintf("ospf router-id %s", ospfConf.RouterID))
	cmds = append(cmds, "exit")

	for _, interfaceConfig := range ospfConf.Interfaces {
		cmds = append(cmds, interfaceConfig.ToCLICommands(ospfConf)...)
	}

	return cmds
}

type MPBGPAddressFamilyConfig struct {
	AFI  string `yaml:"afi" json:"afi"`
	SAFI string `yaml:"safi" json:"safi"`

	// following fields are only supported in (afi=l2vpn, safi=evpn)
	AdvertiseAllVNI *bool `yaml:"advertise_all_vni" json:"advertise_all_vni"`
	AdvertiseSVIIP  *bool `yaml:"advertise_svi_ip" json:"advertise_svi_ip"`
}

func (afConf *MPBGPAddressFamilyConfig) ToCLICommands(bgpConf *BGPConfig) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("address-family %s %s", afConf.AFI, afConf.SAFI))

	if bgpConf.Neighbors != nil {
		for groupName := range bgpConf.Neighbors {
			cmds = append(cmds, fmt.Sprintf("neighbor %s activate", groupName))
		}
	}

	if afConf.AdvertiseAllVNI != nil {
		cmds = append(cmds, "advertise-all-vni")
	}

	if afConf.AdvertiseSVIIP != nil {
		cmds = append(cmds, "advertise-svi-ip")
	}

	cmds = append(cmds, "exit-address-family")

	return cmds
}

type BGPPeerConfig struct {
	Address string `yaml:"address" json:"address"`
}

type BGPNeighborGroupConfig struct {
	Capabilities []string        `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
	Peers        []BGPPeerConfig `yaml:"peers,omitempty" json:"peers,omitempty"`
	ASN          int             `yaml:"asn,omitempty" json:"asn,omitempty"`
}

type BGPConfig struct {
	// Currently only 'default' vrf is supported
	VRF             string                     `yaml:"vrf" json:"vrf"`
	ASN             int                        `yaml:"asn" json:"asn"`
	RouterID        string                     `yaml:"router_id" json:"router_id"`
	NoIPv4Unicast   bool                       `yaml:"no_ipv4_unicast" json:"no_ipv4_unicast"`
	AddressFamilies []MPBGPAddressFamilyConfig `yaml:"address_families" json:"address_families"`

	// key is the group name
	Neighbors map[string]BGPNeighborGroupConfig `yaml:"neighbors" json:"neighbors"`
}

func (bgpNeighborGroupConfig *BGPNeighborGroupConfig) ToCLICommands(groupName string) []string {
	cmds := make([]string, 0)

	cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group", groupName))
	cmds = append(cmds, fmt.Sprintf("neighbor %s remote-as %d", groupName, bgpNeighborGroupConfig.ASN))

	if bgpNeighborGroupConfig.Capabilities != nil {
		for _, capability := range bgpNeighborGroupConfig.Capabilities {
			cmds = append(cmds, fmt.Sprintf("neighbor %s capability %s", groupName, capability))
		}
	}

	if bgpNeighborGroupConfig.Peers != nil {
		for _, peer := range bgpNeighborGroupConfig.Peers {
			cmds = append(cmds, fmt.Sprintf("neighbor %s peer-group %s", peer.Address, groupName))
		}
	}

	return cmds
}

func (bgpConf *BGPConfig) ToCLICommands() []string {
	cmds := make([]string, 0)
	cmds = append(cmds, fmt.Sprintf("router bgp %d vrf %s", bgpConf.ASN, bgpConf.VRF))
	cmds = append(cmds, fmt.Sprintf("bgp router-id %s", bgpConf.RouterID))

	if bgpConf.NoIPv4Unicast {
		cmds = append(cmds, "no bgp default ipv4-unicast")
	}

	if bgpConf.Neighbors != nil {
		for groupName, groupConfig := range bgpConf.Neighbors {
			cmds = append(cmds, groupConfig.ToCLICommands(groupName)...)
		}
	}

	if bgpConf.AddressFamilies != nil {
		for _, afConf := range bgpConf.AddressFamilies {
			cmds = append(cmds, afConf.ToCLICommands(bgpConf)...)
		}
	}

	cmds = append(cmds, "exit")

	return cmds
}

type ControlplaneConfig struct {
	OSPF              []OSPFConfig `yaml:"ospf,omitempty" json:"ospf,omitempty"`
	BGP               []BGPConfig  `yaml:"bgp,omitempty" json:"bgp,omitempty"`
	ContainerName     *string      `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	HostPatchDir      string       `yaml:"host_patch_dir,omitempty" json:"host_patch_dir,omitempty"`
	ContainerPatchDir string       `yaml:"container_patch_dir,omitempty" json:"container_patch_dir,omitempty"`
}

type DummyConfig struct {
	Name          string          `yaml:"name" json:"name"`
	ContainerName *string         `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses     []AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

func getNetlinkAddrKey(addr *netlink.Addr) string {
	if addr == nil {
		return ""
	}

	if addr.Peer != nil {
		return fmt.Sprintf("%s -> %s", addr.IP.String(), addr.Peer.String())
	}

	if addr.IPNet != nil {
		return addr.IPNet.String()
	}

	return addr.IP.String()
}

// returns (added, removed)
func detectAddrChanges(spec []*netlink.Addr, actual []*netlink.Addr) ([]*netlink.Addr, []*netlink.Addr) {
	specMap := make(map[string]*netlink.Addr)
	for _, addr := range spec {
		specMap[getNetlinkAddrKey(addr)] = addr
	}

	actualMap := make(map[string]*netlink.Addr)
	for _, addr := range actual {
		actualMap[getNetlinkAddrKey(addr)] = addr
	}

	added := make([]*netlink.Addr, 0)
	removed := make([]*netlink.Addr, 0)

	for key, addr := range specMap {
		if _, ok := actualMap[key]; !ok {
			added = append(added, addr)
		}
	}

	for key, addr := range actualMap {
		if _, ok := specMap[key]; !ok {
			removed = append(removed, addr)
		}
	}

	return added, removed
}

type DummyInterfaceChangeSet struct {
	ContainerName     *string
	InterfaceName     string
	AddressesToRemove []*netlink.Addr
	AddressesToAdd    []*netlink.Addr
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetContainerName() *string {
	return dummyInterfaceChangeSet.ContainerName
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) GetInterfaceName() string {
	return dummyInterfaceChangeSet.InterfaceName
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) HasUpdates() bool {
	return len(dummyInterfaceChangeSet.AddressesToRemove)+len(dummyInterfaceChangeSet.AddressesToAdd) > 0
}

func (dummyInterfaceChangeSet *DummyInterfaceChangeSet) Apply(ctx context.Context) error {
	if !dummyInterfaceChangeSet.HasUpdates() {
		return nil
	}

	return withNsHandle(ctx, dummyInterfaceChangeSet.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(dummyInterfaceChangeSet.InterfaceName)
		if err == nil && link != nil {

			for _, addr := range dummyInterfaceChangeSet.AddressesToRemove {
				if err := handle.AddrDel(link, addr); err != nil {
					return fmt.Errorf("failed to remove address from dummy link: %w", err)
				}
			}

			for _, addr := range dummyInterfaceChangeSet.AddressesToAdd {
				if err := handle.AddrAdd(link, addr); err != nil {
					return fmt.Errorf("failed to add address to dummy link: %w", err)
				}
			}

		}
		return nil
	})
}

func (dummyConfig *DummyConfig) DetectChanges(ctx context.Context) (InterfaceChangeSet, error) {
	changeSet := new(DummyInterfaceChangeSet)
	for _, addr := range dummyConfig.Addresses {
		nlAddr, err := addr.ToNetlinkAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to netlink addr: %w", err)
		}
		changeSet.AddressesToAdd = append(changeSet.AddressesToAdd, nlAddr)
	}

	withNsHandle(ctx, dummyConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(dummyConfig.Name)
		if err == nil {
			if link != nil {
				addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
				if err == nil {
					for _, addr := range addrs {
						changeSet.AddressesToRemove = append(changeSet.AddressesToRemove, &addr)
					}
				}
			}
		}
		return nil
	})

	changeSet.ContainerName = dummyConfig.ContainerName
	changeSet.InterfaceName = dummyConfig.Name
	changeSet.AddressesToAdd, changeSet.AddressesToRemove = detectAddrChanges(changeSet.AddressesToAdd, changeSet.AddressesToRemove)

	return changeSet, nil
}

func (dummyConfig *DummyConfig) GetContainerName() *string {
	return dummyConfig.ContainerName
}

func (dummyConfig *DummyConfig) GetInterfaceName() string {
	return dummyConfig.Name
}

func (dummyConfig *DummyConfig) Create(ctx context.Context) error {
	return withNsHandle(ctx, dummyConfig.ContainerName, func(handle *netlink.Handle) error {
		link := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name: dummyConfig.Name,
			},
		}

		err := handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add dummy link: %w", err)
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set up dummy link: %w", err)
		}

		for _, addr := range dummyConfig.Addresses {
			nlAddr, err := addr.ToNetlinkAddr()
			if err != nil {
				return fmt.Errorf("failed to convert address to netlink addr: %w", err)
			}
			err = handle.AddrAdd(link, nlAddr)
			if err != nil {
				return fmt.Errorf("failed to add address to dummy link: %w", err)
			}
		}

		return nil
	})
}

type WireGuardPeerConfig struct {
	PublicKey  string   `yaml:"publickey" json:"publickey"`
	Endpoint   *string  `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	AllowedIPs []string `yaml:"allowedips,omitempty" json:"allowedips,omitempty"`
}

func (wgPeerConfig *WireGuardPeerConfig) ToWGTypesPeer() (*wgtypes.PeerConfig, error) {
	peercfg := new(wgtypes.PeerConfig)

	pk, err := wgtypes.ParseKey(wgPeerConfig.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	peercfg.PublicKey = pk

	if wgPeerConfig.Endpoint != nil {
		udpAddr, err := net.ResolveUDPAddr("udp", *wgPeerConfig.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve udp address: %w", err)
		}
		peercfg.Endpoint = udpAddr
	}

	for _, allowedipstr := range wgPeerConfig.AllowedIPs {
		_, ipnet, err := net.ParseCIDR(allowedipstr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed ip: %w", err)
		}
		peercfg.AllowedIPs = append(peercfg.AllowedIPs, *ipnet)
	}

	return peercfg, nil
}

type AddressConfig struct {
	Peer  *string `yaml:"peer,omitempty" json:"peer,omitempty"`
	Local *string `yaml:"local,omitempty" json:"local,omitempty"`
	CIDR  *string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
}

func (addrConfig *AddressConfig) ToNetlinkAddr() (*netlink.Addr, error) {
	if addrConfig.Peer != nil && addrConfig.Local != nil {
		_, peerIPNet, err := net.ParseCIDR(*addrConfig.Peer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer ip: %w", err)
		}

		localIp := net.ParseIP(*addrConfig.Local)
		if localIp == nil {
			return nil, fmt.Errorf("failed to parse local ip: %w", err)
		}

		nlAddr := new(netlink.Addr)
		nlAddr.Peer = peerIPNet
		nlAddr.IPNet = new(net.IPNet)
		nlAddr.IP = localIp

		return nlAddr, nil
	}

	_, ipNet, err := net.ParseCIDR(*addrConfig.CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cidr: %w", err)
	}

	nlAddr := new(netlink.Addr)
	nlAddr.IPNet = ipNet
	return nlAddr, nil
}

type WireGuardConfig struct {
	Name          string                `yaml:"name" json:"name"`
	PrivateKey    string                `yaml:"privatekey" json:"privatekey"`
	Peers         []WireGuardPeerConfig `yaml:"peers,omitempty" json:"peers,omitempty"`
	Addresses     []AddressConfig       `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	ContainerName *string               `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	ListenPort    *int                  `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	MTU           *int                  `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

type WireGuardInterfaceChangeSet struct {
	ContainerName *string
	InterfaceName string

	PrivateKeyToSet *wgtypes.Key
	MTUToSet        *int
	ListenPortToSet *int

	PeersToRemove map[string]*wgtypes.Peer
	PeersToAdd    map[string]wgtypes.PeerConfig

	AddressesToAdd    []*netlink.Addr
	AddressesToRemove []*netlink.Addr
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetContainerName() *string {
	return wgInterfaceChangeSet.ContainerName
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) GetInterfaceName() string {
	return wgInterfaceChangeSet.InterfaceName
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) HasUpdates() bool {
	return wgInterfaceChangeSet != nil && (wgInterfaceChangeSet.PrivateKeyToSet != nil ||
		wgInterfaceChangeSet.MTUToSet != nil ||
		wgInterfaceChangeSet.ListenPortToSet != nil ||
		wgInterfaceChangeSet.PeersToRemove != nil ||
		wgInterfaceChangeSet.PeersToAdd != nil ||
		wgInterfaceChangeSet.AddressesToAdd != nil ||
		wgInterfaceChangeSet.AddressesToRemove != nil)
}

func (wgInterfaceChangeSet *WireGuardInterfaceChangeSet) Apply(ctx context.Context) error {
	if wgInterfaceChangeSet == nil {
		return nil
	}

	if wgInterfaceChangeSet.PrivateKeyToSet != nil || wgInterfaceChangeSet.ListenPortToSet != nil || wgInterfaceChangeSet.PeersToRemove != nil || wgInterfaceChangeSet.PeersToAdd != nil {
		wgCtrl, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to create wireguard controller: %w", err)
		}
		defer wgCtrl.Close()

		currentConfig, err := wgCtrl.Device(wgInterfaceChangeSet.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get wireguard device: %w", err)
		}

		if currentConfig == nil {
			return fmt.Errorf("failed to get wireguard device: %s in %s", wgInterfaceChangeSet.InterfaceName, getContainerDisplayName(wgInterfaceChangeSet.ContainerName))
		}

		if wgInterfaceChangeSet.PrivateKeyToSet != nil {
			patchConfig := new(wgtypes.Config)
			patchConfig.PrivateKey = wgInterfaceChangeSet.PrivateKeyToSet
			if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
				return fmt.Errorf("failed to patch wireguard config: %w", err)
			}
		}

		if wgInterfaceChangeSet.ListenPortToSet != nil {
			patchConfig := new(wgtypes.Config)
			patchConfig.ListenPort = wgInterfaceChangeSet.ListenPortToSet
			if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
				return fmt.Errorf("failed to patch wireguard config: %w", err)
			}
		}

		for _, p := range wgInterfaceChangeSet.PeersToRemove {
			patchConfig := new(wgtypes.Config)
			patchConfig.Peers = make([]wgtypes.PeerConfig, 0)
			patchConfig.ReplacePeers = false
			patchConfig.Peers = append(patchConfig.Peers, wgtypes.PeerConfig{
				PublicKey: p.PublicKey,
				Remove:    true,
			})
			if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
				return fmt.Errorf("failed to patch wireguard config: %w", err)
			}
		}

		for _, p := range wgInterfaceChangeSet.PeersToAdd {
			patchConfig := new(wgtypes.Config)
			patchConfig.Peers = make([]wgtypes.PeerConfig, 0)
			patchConfig.ReplacePeers = false
			patchConfig.Peers = append(patchConfig.Peers, p)
			if err := wgCtrl.ConfigureDevice(wgInterfaceChangeSet.InterfaceName, *patchConfig); err != nil {
				return fmt.Errorf("failed to patch wireguard config: %w", err)
			}
		}
	}

	if wgInterfaceChangeSet.MTUToSet != nil || wgInterfaceChangeSet.ListenPortToSet != nil {
		err := withNsHandle(ctx, wgInterfaceChangeSet.ContainerName, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(wgInterfaceChangeSet.InterfaceName)
			if err != nil {
				return fmt.Errorf("failed to get wireguard link: %w", err)
			}

			if wgInterfaceChangeSet.MTUToSet != nil {
				if err := handle.LinkSetMTU(link, *wgInterfaceChangeSet.MTUToSet); err != nil {
					return fmt.Errorf("failed to set wireguard link mtu: %w", err)
				}
			}

			for _, addr := range wgInterfaceChangeSet.AddressesToRemove {
				if err := handle.AddrDel(link, addr); err != nil {
					return fmt.Errorf("failed to remove wireguard link address: %w", err)
				}
			}

			for _, addr := range wgInterfaceChangeSet.AddressesToAdd {
				if err := handle.AddrAdd(link, addr); err != nil {
					return fmt.Errorf("failed to add wireguard link address: %w", err)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to apply wireguard netlink config: %w", err)
		}
	}

	return nil
}

func (wgConf *WireGuardConfig) GetInterfaceName() string {
	return wgConf.Name
}

func (wgConf *WireGuardConfig) GetContainerName() *string {
	return wgConf.ContainerName
}

func isUDPAddrNotEqu(spec, curr *net.UDPAddr) bool {
	if spec == nil {
		// when spec is nil, always consider them as equal
		return false
	}

	if curr == nil {
		return true
	}

	return spec.String() != curr.String()
}

func isIPNetListNotEqu(lhs, rhs []net.IPNet) bool {
	lhsStrs := make([]string, 0)
	for _, allowedIP := range lhs {
		lhsStrs = append(lhsStrs, allowedIP.String())
	}

	rhsStrs := make([]string, 0)
	for _, allowedIP := range rhs {
		rhsStrs = append(rhsStrs, allowedIP.String())
	}

	sort.Strings(lhsStrs)
	sort.Strings(rhsStrs)

	if len(lhsStrs) != len(rhsStrs) {
		return true
	}

	for i := range lhsStrs {
		if lhsStrs[i] != rhsStrs[i] {
			return true
		}
	}

	return false
}

// returns: (added, removed)
func checkWGPeersDifference(specPeers []wgtypes.PeerConfig, currentPeers []*wgtypes.Peer) (map[string]wgtypes.PeerConfig, map[string]*wgtypes.Peer) {

	commonPeers := make(map[string]wgtypes.PeerConfig)
	specPeersMap := make(map[string]wgtypes.PeerConfig)
	currentPeersMap := make(map[string]*wgtypes.Peer)
	peersToRemove := make(map[string]*wgtypes.Peer)
	peersToAdd := make(map[string]wgtypes.PeerConfig)

	for _, peer := range specPeers {
		specPeersMap[peer.PublicKey.String()] = peer
	}

	for _, peer := range currentPeers {
		k := peer.PublicKey.String()
		currentPeersMap[k] = peer
		if _, ok := specPeersMap[k]; ok {
			commonPeers[k] = specPeersMap[k]
		} else {
			peersToRemove[k] = peer
		}
	}

	for _, peer := range specPeers {
		if _, ok := currentPeersMap[peer.PublicKey.String()]; !ok {
			peersToAdd[peer.PublicKey.String()] = peer
		}
	}

	for k, spec := range commonPeers {
		peer := currentPeersMap[k]
		if spec.PresharedKey != nil && *spec.PresharedKey != peer.PresharedKey {
			peersToRemove[k] = peer
			peersToAdd[k] = spec
		}

		if isUDPAddrNotEqu(spec.Endpoint, peer.Endpoint) {
			peersToRemove[k] = peer
			peersToAdd[k] = spec
		}

		if spec.PersistentKeepaliveInterval != nil {
			if *spec.PersistentKeepaliveInterval != peer.PersistentKeepaliveInterval {
				peersToRemove[k] = peer
				peersToAdd[k] = spec
			}
		}

		if isIPNetListNotEqu(spec.AllowedIPs, peer.AllowedIPs) {
			peersToRemove[k] = peer
			peersToAdd[k] = spec
		}
	}

	return peersToAdd, peersToRemove
}

func (wgConf *WireGuardConfig) DetectChanges(ctx context.Context) (InterfaceChangeSet, error) {
	changeSet := new(WireGuardInterfaceChangeSet)
	changeSet.ContainerName = wgConf.ContainerName
	changeSet.InterfaceName = wgConf.Name

	wgCtrl, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wireguard controller: %w", err)
	}
	defer wgCtrl.Close()

	currentConfig, err := wgCtrl.Device(wgConf.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get wireguard device: %w", err)
	}

	if currentConfig == nil {
		return nil, fmt.Errorf("failed to get wireguard device: %s in %s", wgConf.Name, getContainerDisplayName(wgConf.ContainerName))
	}

	specPeerConfigs := make([]wgtypes.PeerConfig, 0)
	for _, peer := range wgConf.Peers {
		peercfg, err := peer.ToWGTypesPeer()
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer to wgtypes peer: %w", err)
		}
		specPeerConfigs = append(specPeerConfigs, *peercfg)
	}

	currPeers := make([]*wgtypes.Peer, 0)
	for _, peer := range currentConfig.Peers {
		currPeers = append(currPeers, &peer)
	}

	addedPeers, removedPeers := checkWGPeersDifference(specPeerConfigs, currPeers)
	changeSet.PeersToAdd = addedPeers
	changeSet.PeersToRemove = removedPeers

	wgtypesConf, err := wgConf.ToWGTypesConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to convert wireguard config to wgtypes config: %w", err)
	}

	if wgtypesConf.PrivateKey != nil {
		if *wgtypesConf.PrivateKey != currentConfig.PrivateKey {
			changeSet.PrivateKeyToSet = wgtypesConf.PrivateKey
		}
	}

	if wgtypesConf.ListenPort != nil {
		if *wgtypesConf.ListenPort != currentConfig.ListenPort {
			changeSet.ListenPortToSet = wgtypesConf.ListenPort
		}
	}

	return changeSet, nil
}

func (wgConf *WireGuardConfig) ToWGTypesConfig() (*wgtypes.Config, error) {
	wgtypesConf := new(wgtypes.Config)

	if wgConf.ListenPort != nil {
		wgtypesConf.ListenPort = wgConf.ListenPort
	}

	if wgConf.PrivateKey != "" {
		pk, err := wgtypes.ParseKey(wgConf.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		wgtypesConf.PrivateKey = &pk
	}

	for _, peer := range wgConf.Peers {
		peercfg, err := peer.ToWGTypesPeer()
		if err != nil {
			return nil, fmt.Errorf("failed to convert peer to wgtypes peer: %w", err)
		}
		wgtypesConf.Peers = append(wgtypesConf.Peers, *peercfg)
	}

	return wgtypesConf, nil
}

func (wgConf *WireGuardConfig) Create(ctx context.Context) error {
	return withNsHandle(ctx, nil, func(handle *netlink.Handle) error {
		link := &netlink.Wireguard{
			LinkAttrs: netlink.LinkAttrs{
				Name: wgConf.Name,
			},
		}

		if wgConf.MTU != nil {
			link.MTU = *wgConf.MTU
		}

		if err := handle.LinkAdd(link); err != nil {
			return fmt.Errorf("failed to add wireguard link: %w", err)
		}

		wgCtrl, err := wgctrl.New()
		if err != nil {
			return fmt.Errorf("failed to create wireguard controller: %w", err)
		}
		defer wgCtrl.Close()

		wgtypesConf, err := wgConf.ToWGTypesConfig()
		if err != nil {
			return fmt.Errorf("failed to convert wireguard config to wgtypes config: %w", err)
		}

		if err := wgCtrl.ConfigureDevice(wgConf.Name, *wgtypesConf); err != nil {
			return fmt.Errorf("failed to configure wireguard device: %w", err)
		}

		if err := handle.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set wireguard link up: %w", err)
		}

		if wgConf.ContainerName != nil {
			cli, err := dockerCliFromCtx(ctx)
			if err != nil {
				return fmt.Errorf("failed to get docker cli from context: %w", err)
			}

			pidPtr, err := getContainerNSPid(ctx, cli, *wgConf.ContainerName)
			if err != nil {
				return fmt.Errorf("failed to get container ns pid: %w", err)
			}
			if pidPtr != nil {
				if err := netlink.LinkSetNsPid(link, int(*pidPtr)); err != nil {
					return fmt.Errorf("failed to set wireguard link ns pid: %w", err)
				}
			}
		}

		return withNsHandle(ctx, wgConf.ContainerName, func(handle *netlink.Handle) error {
			link, err := handle.LinkByName(wgConf.Name)
			if err != nil {
				return fmt.Errorf("failed to get wireguard link: %w", err)
			}

			if err := handle.LinkSetUp(link); err != nil {
				return fmt.Errorf("failed to set wireguard link up: %w", err)
			}

			for _, peer := range wgConf.Addresses {
				nlAddr, err := peer.ToNetlinkAddr()
				if err != nil {
					return fmt.Errorf("failed to convert address to netlink addr: %w", err)
				}
				err = handle.AddrAdd(link, nlAddr)
				if err != nil {
					return fmt.Errorf("failed to add address to wireguard link: %w", err)
				}
			}

			return nil
		})
	})
}

type ContainerDockerConfig struct {
	Name string `yaml:"name" json:"name"`
}

type ContainerConfig struct {
	Docker ContainerDockerConfig `yaml:"docker,omitempty" json:"docker,omitempty"`
}

type VXLANConfig struct {
	Name          string          `yaml:"name" json:"name"`
	VXLANID       int             `yaml:"vxlan_id" json:"vxlan_id"`
	LocalIP       *string         `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	MTU           *int            `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	Nolearning    *bool           `yaml:"nolearning,omitempty" json:"nolearning,omitempty"`
	ContainerName *string         `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Addresses     []AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type VXLANInterfaceChangeSet struct {
	AddressesToAdd    []*netlink.Addr
	AddressedToRemove []*netlink.Addr
	MTUToSet          *int
	ContainerName     *string
	InterfaceName     string
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetContainerName() *string {
	return vxlanInterfaceChangeSet.ContainerName
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) GetInterfaceName() string {
	return vxlanInterfaceChangeSet.InterfaceName
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) HasUpdates() bool {
	return vxlanInterfaceChangeSet != nil && (len(vxlanInterfaceChangeSet.AddressesToAdd) > 0 ||
		len(vxlanInterfaceChangeSet.AddressedToRemove) > 0 ||
		vxlanInterfaceChangeSet.MTUToSet != nil)
}

func (vxlanInterfaceChangeSet *VXLANInterfaceChangeSet) Apply(ctx context.Context) error {
	if vxlanInterfaceChangeSet == nil {
		return nil
	}

	return withNsHandle(ctx, vxlanInterfaceChangeSet.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vxlanInterfaceChangeSet.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get vxlan link: %w", err)
		}

		for _, addr := range vxlanInterfaceChangeSet.AddressedToRemove {
			if err := handle.AddrDel(link, addr); err != nil {
				return fmt.Errorf("failed to remove address from vxlan link: %w", err)
			}
		}

		for _, addr := range vxlanInterfaceChangeSet.AddressesToAdd {
			if err := handle.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add address to vxlan link: %w", err)
			}
		}

		if vxlanInterfaceChangeSet.MTUToSet != nil {
			if err := handle.LinkSetMTU(link, *vxlanInterfaceChangeSet.MTUToSet); err != nil {
				return fmt.Errorf("failed to set vxlan link mtu: %w", err)
			}
		}

		return nil
	})
}

func (vxlanConfig *VXLANConfig) DetectChanges(ctx context.Context) (InterfaceChangeSet, error) {
	changeSet := new(VXLANInterfaceChangeSet)
	changeSet.ContainerName = vxlanConfig.ContainerName
	changeSet.InterfaceName = vxlanConfig.Name

	err := withNsHandle(ctx, vxlanConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vxlanConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get vxlan link: %w", err)
		}

		if vxlanConfig.MTU != nil {
			if *vxlanConfig.MTU != link.Attrs().MTU {
				changeSet.MTUToSet = vxlanConfig.MTU
			}
		}

		specAddrs := make([]*netlink.Addr, 0)
		for _, addr := range vxlanConfig.Addresses {
			nlAddr, err := addr.ToNetlinkAddr()
			if err != nil {
				return fmt.Errorf("failed to convert address to netlink addr: %w", err)
			}
			specAddrs = append(specAddrs, nlAddr)
		}

		actualAddrPtrs := make([]*netlink.Addr, 0)
		actualAddrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("failed to list vxlan link addresses: %w", err)
		}
		for _, addr := range actualAddrs {
			actualAddrPtrs = append(actualAddrPtrs, &addr)
		}

		changeSet.AddressesToAdd, changeSet.AddressedToRemove = detectAddrChanges(specAddrs, actualAddrPtrs)

		return nil
	})

	return changeSet, err
}

func (vxlanConfig *VXLANConfig) GetContainerName() *string {
	return vxlanConfig.ContainerName
}

func (vxlanConfig *VXLANConfig) GetInterfaceName() string {
	return vxlanConfig.Name
}

func findContainer(ctx context.Context, cli *client.Client, containerName string) (*container.Summary, error) {
	filters := filters.NewArgs()
	filters.Add("name", containerName)

	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: filters,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		return nil, nil
	}

	return &containers[0], nil
}

func getNetNSHandle(ctx context.Context, cli *client.Client, containerName string) (netns.NsHandle, error) {
	container, err := findContainer(ctx, cli, containerName)
	if err != nil {
		return -1, fmt.Errorf("failed to find container: %w", err)
	}

	if container == nil {
		return -1, fmt.Errorf("container %s not found", containerName)
	}

	return netns.GetFromDocker(container.ID)
}

func getContainerNSPid(ctx context.Context, cli *client.Client, containerName string) (*int, error) {
	container, err := findContainer(ctx, cli, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to find container: %w", err)
	}

	if container == nil {
		return nil, fmt.Errorf("container %s not found", containerName)
	}

	resp, err := cli.ContainerInspect(ctx, container.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	return &resp.State.Pid, nil
}

func withNsHandle(ctx context.Context, containerName *string, f func(h *netlink.Handle) error) error {
	if containerName == nil {
		handle, err := netlink.NewHandle()
		if err != nil {
			return fmt.Errorf("failed to create netlink handle: %w", err)
		}
		defer handle.Close()
		return f(handle)
	}

	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}
	nsHandle, err := getNetNSHandle(ctx, cli, *containerName)
	if err != nil {
		return fmt.Errorf("failed to get netns from docker: %w", err)
	}
	defer nsHandle.Close()

	handle, err := netlink.NewHandleAt(nsHandle)
	if err != nil {
		return fmt.Errorf("failed to create netlink handle: %w", err)
	}
	defer handle.Close()

	return f(handle)
}

func (vxlanConfig *VXLANConfig) Create(ctx context.Context) error {
	return withNsHandle(ctx, vxlanConfig.ContainerName, func(handle *netlink.Handle) error {
		var err error

		link := &netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name: vxlanConfig.Name,
			},
			VxlanId: vxlanConfig.VXLANID,
		}

		if vxlanConfig.LocalIP != nil {
			srcAddr := net.ParseIP(*vxlanConfig.LocalIP)
			if srcAddr == nil {
				return fmt.Errorf("failed to parse local ip: %w", err)
			}
			link.SrcAddr = srcAddr
		}

		if vxlanConfig.MTU != nil {
			link.MTU = *vxlanConfig.MTU
		}

		if vxlanConfig.Nolearning != nil {
			link.Learning = !*vxlanConfig.Nolearning
		}

		err = handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add vxlan link: %w", err)
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set vxlan link up: %w", err)
		}

		return nil
	})
}

type VethPairConfig struct {
	Name          string          `yaml:"name" json:"name"`
	ContainerName *string         `yaml:"container_name,omitempty" json:"container_name,omitempty"`
	Peer          *VethPairConfig `yaml:"peer,omitempty" json:"peer,omitempty"`
	Addresses     []AddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
	MTU           *int            `yaml:"mtu,omitempty" json:"mtu,omitempty"`
}

type VethPairChangeSet struct {
	Local *VethPairPeerChangeSet
	Peer  *VethPairPeerChangeSet
}

func (vethPair *VethPairChangeSet) GetContainerName() *string {
	return vethPair.Local.ContainerName
}

func (vethPair *VethPairChangeSet) GetInterfaceName() string {
	return vethPair.Local.InterfaceName
}

func (vethPair *VethPairChangeSet) HasUpdates() bool {
	return vethPair != nil && (vethPair.Local.HasUpdates() || vethPair.Peer.HasUpdates())
}

func (vethPair *VethPairChangeSet) Apply(ctx context.Context) error {
	if vethPair != nil {
		if err := vethPair.Local.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply local veth pair: %w", err)
		}
		if err := vethPair.Peer.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply peer veth pair: %w", err)
		}
		return nil
	}

	return nil
}

type VethPairPeerChangeSet struct {
	ContainerName  *string
	InterfaceName  string
	AddressesToAdd []*netlink.Addr
	AddressesToDel []*netlink.Addr
	MTUToSet       *int
}

func (vethPeer *VethPairPeerChangeSet) HasUpdates() bool {
	return vethPeer != nil && (len(vethPeer.AddressesToAdd) > 0 || len(vethPeer.AddressesToDel) > 0 || vethPeer.MTUToSet != nil)
}

func (vethPeer *VethPairPeerChangeSet) Apply(ctx context.Context) error {
	if vethPeer == nil {
		return nil
	}

	return withNsHandle(ctx, vethPeer.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(vethPeer.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get veth link: %w", err)
		}

		for _, addr := range vethPeer.AddressesToDel {
			if err := handle.AddrDel(link, addr); err != nil {
				return fmt.Errorf("failed to remove address from veth link: %w", err)
			}
		}

		for _, addr := range vethPeer.AddressesToAdd {
			if err := handle.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add address to veth link: %w", err)
			}
		}

		if vethPeer.MTUToSet != nil {
			if err := handle.LinkSetMTU(link, *vethPeer.MTUToSet); err != nil {
				return fmt.Errorf("failed to set veth link mtu: %w", err)
			}
		}

		return nil
	})
}

func NewVethPairPeerChangeSet(containerName *string, interfaceName string, spec *VethPairConfig, handle *netlink.Handle) (*VethPairPeerChangeSet, error) {

	changeSet := new(VethPairPeerChangeSet)
	changeSet.ContainerName = containerName
	changeSet.InterfaceName = interfaceName

	link, err := handle.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get veth link: %w", err)
	}

	if spec.MTU != nil {
		if *spec.MTU != link.Attrs().MTU {
			changeSet.MTUToSet = spec.MTU
		}
	}

	specAddrs := make([]*netlink.Addr, 0)
	for _, addr := range spec.Addresses {
		nlAddr, err := addr.ToNetlinkAddr()
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to netlink addr: %w", err)
		}
		specAddrs = append(specAddrs, nlAddr)
	}
	actualAddrPtrs := make([]*netlink.Addr, 0)
	actualAddrs, err := handle.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to list veth link addresses: %w", err)
	}
	for _, addr := range actualAddrs {
		actualAddrPtrs = append(actualAddrPtrs, &addr)
	}
	changeSet.AddressesToAdd, changeSet.AddressesToDel = detectAddrChanges(specAddrs, actualAddrPtrs)

	return changeSet, nil
}

func (vethPairConfig *VethPairConfig) DetectChanges(ctx context.Context) (InterfaceChangeSet, error) {
	changeSet := new(VethPairChangeSet)

	// Detecting local changeset
	err := withNsHandle(ctx, vethPairConfig.ContainerName, func(handle *netlink.Handle) error {
		localChangeSet, err := NewVethPairPeerChangeSet(vethPairConfig.ContainerName, vethPairConfig.Name, vethPairConfig, handle)
		if err != nil {
			return fmt.Errorf("failed to detect local changeset: %w", err)
		}
		changeSet.Local = localChangeSet
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	// Detecting peer changeset
	err = withNsHandle(ctx, vethPairConfig.Peer.ContainerName, func(handle *netlink.Handle) error {
		peerChangeSet, err := NewVethPairPeerChangeSet(vethPairConfig.Peer.ContainerName, vethPairConfig.Peer.Name, vethPairConfig.Peer, handle)
		if err != nil {
			return fmt.Errorf("failed to detect peer changeset: %w", err)
		}
		changeSet.Peer = peerChangeSet
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to detect changeset: %w", err)
	}

	return changeSet, err
}

func (vethPairConfig *VethPairConfig) GetContainerName() *string {
	return vethPairConfig.ContainerName
}

func (vethPairConfig *VethPairConfig) GetInterfaceName() string {
	return vethPairConfig.Name
}

func (vethPairConfig *VethPairConfig) Create(ctx context.Context) error {
	return withNsHandle(ctx, nil, func(handle *netlink.Handle) error {
		cli, err := dockerCliFromCtx(ctx)
		if err != nil {
			return fmt.Errorf("failed to get docker cli from context: %w", err)
		}

		if vethPairConfig.Peer == nil {
			return fmt.Errorf("peer is not set")
		}

		link := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: vethPairConfig.Name,
			},
			PeerName: vethPairConfig.Peer.Name,
		}

		if vethPairConfig.ContainerName != nil {
			pidPtr, err := getContainerNSPid(ctx, cli, *vethPairConfig.ContainerName)
			if err != nil {
				return fmt.Errorf("failed to get container ns pid: %w", err)
			}
			if pidPtr != nil {
				link.Namespace = netlink.NsPid(*pidPtr)
			}
		}

		if vethPairConfig.Peer.ContainerName != nil {
			pidPtr, err := getContainerNSPid(ctx, cli, *vethPairConfig.Peer.ContainerName)
			if err != nil {
				return fmt.Errorf("failed to get container ns pid: %w", err)
			}
			if pidPtr != nil {
				link.PeerNamespace = netlink.NsPid(*pidPtr)
			}
		}

		err = handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add veth link: %w", err)
		}

		err = withNsHandle(ctx, vethPairConfig.ContainerName, func(handle *netlink.Handle) error {
			return handle.LinkSetUp(link)
		})
		if err != nil {
			return fmt.Errorf("failed to set veth link up: %w", err)
		}

		err = withNsHandle(ctx, vethPairConfig.Peer.ContainerName, func(handle *netlink.Handle) error {
			return handle.LinkSetUp(link)
		})
		if err != nil {
			return fmt.Errorf("failed to set veth link up: %w", err)
		}

		return nil
	})
}

type BridgeConfig struct {
	Name            string   `yaml:"name" json:"name"`
	SlaveInterfaces []string `yaml:"slave_interfaces,omitempty" json:"slave_interfaces,omitempty"`
	ContainerName   *string  `yaml:"container_name,omitempty" json:"container_name,omitempty"`
}

type BridgeChangeSet struct {
	InterfaceToEnslave map[string]interface{}
	InterfaceToUnslave map[string]interface{}
	ContainerName      *string
	InterfaceName      string
}

func (bridgeChangeSet *BridgeChangeSet) Apply(ctx context.Context) error {
	return withNsHandle(ctx, bridgeChangeSet.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeChangeSet.InterfaceName)
		if err != nil {
			return fmt.Errorf("failed to get bridge link: %w", err)
		}

		for slaveInterface := range bridgeChangeSet.InterfaceToUnslave {
			lk, err := handle.LinkByName(slaveInterface)
			if err == nil && lk != nil {
				if err := handle.LinkSetNoMaster(lk); err != nil {
					return fmt.Errorf("failed to set slave link no master: %w", err)
				}
			}
		}

		for slaveInterface := range bridgeChangeSet.InterfaceToEnslave {
			lk, err := handle.LinkByName(slaveInterface)
			if err == nil && lk != nil {
				if err := handle.LinkSetMaster(lk, link); err != nil {
					return fmt.Errorf("failed to set slave link master: %w", err)
				}
			}
		}

		return nil
	})
}

func (bridgeChangeSet *BridgeChangeSet) GetContainerName() *string {
	return bridgeChangeSet.ContainerName
}

func (bridgeChangeSet *BridgeChangeSet) GetInterfaceName() string {
	return bridgeChangeSet.InterfaceName
}

func (bridgeChangeSet *BridgeChangeSet) HasUpdates() bool {
	return bridgeChangeSet != nil && (len(bridgeChangeSet.InterfaceToEnslave)+len(bridgeChangeSet.InterfaceToUnslave) > 0)
}

func (bridgeConfig *BridgeConfig) DetectChanges(ctx context.Context) (InterfaceChangeSet, error) {
	changeSet := new(BridgeChangeSet)
	changeSet.ContainerName = bridgeConfig.ContainerName
	changeSet.InterfaceName = bridgeConfig.Name
	changeSet.InterfaceToEnslave = make(map[string]interface{})
	changeSet.InterfaceToUnslave = make(map[string]interface{})

	err := withNsHandle(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get bridge link: %w", err)
		}

		enslavedLinks, err := getEnslavedLinks(handle, link)
		if err != nil {
			return fmt.Errorf("failed to get enslaved links: %w", err)
		}

		specSlaveIfs := make(map[string]interface{})
		for _, slaveInterface := range bridgeConfig.SlaveInterfaces {
			specSlaveIfs[slaveInterface] = true
			if _, ok := enslavedLinks[slaveInterface]; ok {
				changeSet.InterfaceToEnslave[slaveInterface] = true
			}
		}

		for _, slif := range enslavedLinks {
			if _, ok := specSlaveIfs[slif.Attrs().Name]; !ok {
				changeSet.InterfaceToUnslave[slif.Attrs().Name] = true
			}
		}

		return nil
	})

	return changeSet, err
}

func (bridgeConfig *BridgeConfig) GetContainerName() *string {
	return bridgeConfig.ContainerName
}

func (bridgeConfig *BridgeConfig) GetInterfaceName() string {
	return bridgeConfig.Name
}

// returns: (added, removed)
// added is those in lhs but not rhs, removed is those in rhs but not lhs
func diffSets(lhs, rhs map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	added := make(map[string]interface{})
	for k, v := range lhs {
		if _, ok := rhs[k]; !ok {
			added[k] = v
		}
	}

	removed := make(map[string]interface{})
	for k, v := range rhs {
		if _, ok := lhs[k]; !ok {
			removed[k] = v
		}
	}

	return added, removed
}

func getEnslavedLinks(handle *netlink.Handle, master netlink.Link) (map[string]netlink.Link, error) {
	allNLLinks, err := handle.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to get all netlink links: %s", err.Error())
	}

	enslavedNLLinks := make(map[string]netlink.Link)
	for _, lk := range allNLLinks {
		if lk.Attrs().MasterIndex == master.Attrs().Index {
			enslavedNLLinks[lk.Attrs().Name] = lk
		}
	}

	return enslavedNLLinks, nil
}

func (bridgeConfig *BridgeConfig) ReconcileEnclaves(ctx context.Context) (map[string]interface{}, map[string]interface{}, error) {
	var added map[string]interface{}
	var removed map[string]interface{}
	actuallyAdded := make(map[string]interface{})
	actuallyRemoved := make(map[string]interface{})

	err := withNsHandle(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(bridgeConfig.Name)
		if err != nil {
			return fmt.Errorf("failed to get bridge link: %w", err)
		}

		specSlaveIfs := make(map[string]interface{})
		for _, slaveInterface := range bridgeConfig.SlaveInterfaces {
			specSlaveIfs[slaveInterface] = slaveInterface
		}

		slaveLinks, err := getEnslavedLinks(handle, link)
		if err != nil {
			return fmt.Errorf("failed to get enslaved links: %w", err)
		}
		slaveLinksMap := make(map[string]interface{})
		for _, slaveLink := range slaveLinks {
			slaveLinksMap[slaveLink.Attrs().Name] = slaveLink
		}

		added, removed = diffSets(specSlaveIfs, slaveLinksMap)
		for removeSlaveIfName := range removed {
			l, err := handle.LinkByName(removeSlaveIfName)
			if err == nil && l != nil {
				if err := netlink.LinkSetNoMaster(l); err != nil {
					return fmt.Errorf("failed to set slave link no master: %w", err)
				}
				actuallyRemoved[removeSlaveIfName] = removeSlaveIfName
			}
		}

		for addedSlaveIfName := range added {
			lk, err := handle.LinkByName(addedSlaveIfName)
			if err == nil && lk != nil {
				if err := handle.LinkSetMaster(lk, link); err != nil {
					return fmt.Errorf("failed to set slave link master: %w", err)
				}
				actuallyAdded[addedSlaveIfName] = addedSlaveIfName
			}
		}

		return nil
	})

	return actuallyAdded, actuallyRemoved, err
}

func (bridgeConfig *BridgeConfig) Create(ctx context.Context) error {
	return withNsHandle(ctx, bridgeConfig.ContainerName, func(handle *netlink.Handle) error {
		link := &netlink.Bridge{
			LinkAttrs: netlink.LinkAttrs{
				Name: bridgeConfig.Name,
			},
		}

		err := handle.LinkAdd(link)
		if err != nil {
			return fmt.Errorf("failed to add bridge link: %w", err)
		}

		err = handle.LinkSetUp(link)
		if err != nil {
			return fmt.Errorf("failed to set bridge link up: %w", err)
		}

		_, _, err = bridgeConfig.ReconcileEnclaves(ctx)
		return err
	})
}

type OpenVPN2ConfigurationList []OpenVPN2Instance

func (ovpList OpenVPN2ConfigurationList) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {
	// Reconciliaton of container-based OpenVPN instances is quite simple, rules:
	// 1. If the container is present on the system but not in the list, remove it.
	// 2. If the container is not present on the system but in the list, create it.
	// 3. If the container is present both on the system and the list, by optimistic assumption, it doesn't need to be updated.
	// 4. The key is the container name, forget about the interface name.

	changeSet := new(DataplaneChangeSet)

	serviceName, err := serviceNameFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get service name: %w", err)
	}

	containerList, err := NewContainerListFromServiceName(ctx, serviceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get container list from service name: %w", err)
	}

	addedSet := make(map[string][]InterfaceProvisioner)
	removedSet := make(map[string][]InterfaceCanceller)
	updatedSet := make(map[string][]InterfaceChangeSet)

	specMap := make(map[string]OpenVPN2Instance)
	for _, c := range ovpList {
		specMap[c.DockerContainer.ContainerName] = c
	}

	containersMap := make(map[string]interface{})
	for _, container := range containerList.GetContainers() {
		containersMap[container.Names[0]] = container
		if _, ok := specMap[container.Names[0]]; !ok {
			removedSet[container.Names[0]] = make([]InterfaceCanceller, 0)
			removedSet[container.Names[0]] = append(removedSet[container.Names[0]], &OpenVPN2InterfaceCanceller{ContainerName: container.Names[0]})
		}
	}

	for _, c := range specMap {
		if _, ok := containersMap[c.DockerContainer.ContainerName]; !ok {
			addedSet[c.DockerContainer.ContainerName] = make([]InterfaceProvisioner, 0)
			addedSet[c.DockerContainer.ContainerName] = append(addedSet[c.DockerContainer.ContainerName], &c)
		}
	}

	changeSet.AddedInterfaces = addedSet
	changeSet.RemovedInterfaces = removedSet
	changeSet.UpdatedInterfaces = updatedSet

	return changeSet, nil
}

type WireGuardConfigurationList []WireGuardConfig

type ContainerKey string

const (
	ContainerKeyHost ContainerKey = "-"
)

func getContainerKey(containerName *string) ContainerKey {
	if containerName == nil {
		return ContainerKeyHost
	}

	if *containerName == "" || *containerName == "-" {
		return ContainerKeyHost
	}

	return ContainerKey(*containerName)
}

func getInterfaceFromContainer(ctx context.Context, containerName *string, linkType string) (map[string]InterfaceCanceller, error) {
	type result struct {
		ifaces map[string]InterfaceCanceller
	}

	res := new(result)
	res.ifaces = make(map[string]InterfaceCanceller, 0)

	err := withNsHandle(ctx, containerName, func(handle *netlink.Handle) error {
		links, err := handle.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list links: %w", err)
		}

		for _, link := range links {
			if link.Type() == linkType {
				res.ifaces[link.Attrs().Name] = &StubInterfaceCanceller{ContainerName: containerName, InterfaceName: link.Attrs().Name}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to get interface from container: %w", err)
	}

	return res.ifaces, nil
}

func detectChangesFromProvisionerList(ctx context.Context, provisionerList []InterfaceProvisioner, netlinkIfType string, containers []string) (*DataplaneChangeSet, error) {
	// key is the container name, for default netns, the key will be '-', value is the list of interfaces present in the container
	currentInterfaceListMap := make(map[string]map[string]InterfaceCanceller)
	for _, name := range containers {
		ifaces, err := getInterfaceFromContainer(ctx, &name, netlinkIfType)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface from container: %w", err)
		}
		currentInterfaceListMap[name] = ifaces
	}
	hostInterfaceList, err := getInterfaceFromContainer(ctx, nil, netlinkIfType)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface from host: %w", err)
	}
	currentInterfaceListMap[string(ContainerKeyHost)] = hostInterfaceList

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces present in the spec
	specInterfaceListMap := make(map[string]map[string]InterfaceProvisioner)
	for _, c := range provisionerList {
		contName := string(getContainerKey(c.GetContainerName()))

		if _, ok := specInterfaceListMap[contName]; !ok {
			specInterfaceListMap[contName] = make(map[string]InterfaceProvisioner, 0)
		}
		specInterfaceListMap[contName][c.GetInterfaceName()] = c
	}

	combinedNsMap := make(map[string]interface{})
	for k := range currentInterfaceListMap {
		combinedNsMap[k] = true
	}
	for k := range specInterfaceListMap {
		combinedNsMap[k] = true
	}

	addedSet := make(map[string][]InterfaceProvisioner)
	removedSet := make(map[string][]InterfaceCanceller)
	updatedSet := make(map[string][]InterfaceChangeSet)

	for nsKey := range combinedNsMap {
		lhsSpecMap, lhsOk := specInterfaceListMap[nsKey]
		rhsCurrentMap, rhsOk := currentInterfaceListMap[nsKey]

		if !lhsOk {
			if rhsOk {
				removedSet[nsKey] = make([]InterfaceCanceller, 0)
				for _, canceller := range rhsCurrentMap {
					removedSet[nsKey] = append(removedSet[nsKey], canceller)
				}
			}
			continue
		}

		if !rhsOk {
			if lhsOk {
				addedSet[nsKey] = make([]InterfaceProvisioner, 0)
				for _, spec := range lhsSpecMap {
					addedSet[nsKey] = append(addedSet[nsKey], spec)
				}
			}
			continue
		}

		updatedSet[nsKey] = make([]InterfaceChangeSet, 0)
		addedSet[nsKey] = make([]InterfaceProvisioner, 0)
		removedSet[nsKey] = make([]InterfaceCanceller, 0)
		commonSet := make(map[string]InterfaceProvisioner)

		for _, status := range rhsCurrentMap {
			if _, ok := lhsSpecMap[status.GetInterfaceName()]; !ok {
				removedSet[nsKey] = append(removedSet[nsKey], status)
			}
		}

		for _, spec := range lhsSpecMap {
			if _, ok := rhsCurrentMap[spec.GetInterfaceName()]; ok {
				commonSet[spec.GetInterfaceName()] = spec
			}

			if _, ok := rhsCurrentMap[spec.GetInterfaceName()]; !ok {
				addedSet[nsKey] = append(addedSet[nsKey], spec)
			}
		}

		for _, spec := range commonSet {
			changes, err := spec.DetectChanges(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to detect changes for WireGuard: %w", err)
			}
			if changes != nil && changes.HasUpdates() {
				updatedSet[nsKey] = append(updatedSet[nsKey], changes)
			}
		}
	}

	result := new(DataplaneChangeSet)
	result.AddedInterfaces = addedSet
	result.RemovedInterfaces = removedSet
	result.UpdatedInterfaces = updatedSet
	return result, nil
}

// Scan containers specified for any reconciliation clues.
func (wgList WireGuardConfigurationList) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {
	wgty := new(netlink.Wireguard).Type()
	provisionerList := make([]InterfaceProvisioner, 0)
	for _, wg := range wgList {
		provisionerList = append(provisionerList, &wg)
	}
	return detectChangesFromProvisionerList(ctx, provisionerList, wgty, containers)
}

type VXLANConfigurationList []VXLANConfig

func (vxlanList VXLANConfigurationList) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {
	vxlanty := new(netlink.Vxlan).Type()
	provisionerList := make([]InterfaceProvisioner, 0)
	for _, vxlan := range vxlanList {
		provisionerList = append(provisionerList, &vxlan)
	}
	return detectChangesFromProvisionerList(ctx, provisionerList, vxlanty, containers)
}

type VethPairConfigurationList []VethPairConfig

func (vethPairList VethPairConfigurationList) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {
	vethPairTy := new(netlink.Veth).Type()
	provisionerList := make([]InterfaceProvisioner, 0)
	for _, vethPair := range vethPairList {
		provisionerList = append(provisionerList, &vethPair)
	}
	return detectChangesFromProvisionerList(ctx, provisionerList, vethPairTy, containers)
}

type BridgeConfigurationList []BridgeConfig

func (bridgeList BridgeConfigurationList) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {
	bridgeTy := new(netlink.Bridge).Type()
	provisionerList := make([]InterfaceProvisioner, 0)
	for _, bridge := range bridgeList {
		provisionerList = append(provisionerList, &bridge)
	}
	return detectChangesFromProvisionerList(ctx, provisionerList, bridgeTy, containers)
}

type DummyConfigurationList []DummyConfig

func (dummyList DummyConfigurationList) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {
	dummyTy := new(netlink.Dummy).Type()
	provisionerList := make([]InterfaceProvisioner, 0)
	for _, dummy := range dummyList {
		provisionerList = append(provisionerList, &dummy)
	}
	return detectChangesFromProvisionerList(ctx, provisionerList, dummyTy, containers)
}

type DataplaneConfig struct {
	OpenVPN   OpenVPN2ConfigurationList  `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
	WireGuard WireGuardConfigurationList `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`
	VXLAN     VXLANConfigurationList     `yaml:"vxlan,omitempty" json:"vxlan,omitempty"`
	VethPair  VethPairConfigurationList  `yaml:"veth,omitempty" json:"veth,omitempty"`
	Bridge    BridgeConfigurationList    `yaml:"bridge,omitempty" json:"bridge,omitempty"`
	Dummy     DummyConfigurationList     `yaml:"dummy,omitempty" json:"dummy,omitempty"`
}

func (dpConfig *DataplaneConfig) DetectChanges(ctx context.Context, containers []string) (*DataplaneChangeSet, error) {

	var changeSet *DataplaneChangeSet

	log.Println("Detecting changes for OpenVPN ...")
	openVPNChangeSet, err := dpConfig.OpenVPN.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for OpenVPN: %w", err)
	}
	if openVPNChangeSet != nil && openVPNChangeSet.HasChanges() {
		log.Println("Found changes for OpenVPN dataplane config")
	}
	changeSet = changeSet.Merge(openVPNChangeSet)

	log.Println("Detecting changes for WireGuard ...")
	wireGuardChangeSet, err := dpConfig.WireGuard.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for WireGuard: %w", err)
	}
	if wireGuardChangeSet != nil && wireGuardChangeSet.HasChanges() {
		log.Println("Found changes for WireGuard dataplane config")
	}
	changeSet = changeSet.Merge(wireGuardChangeSet)

	log.Println("Detecting changes for VXLAN ...")
	vxlanChangeSet, err := dpConfig.VXLAN.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for VXLAN: %w", err)
	}
	if vxlanChangeSet != nil && vxlanChangeSet.HasChanges() {
		log.Println("Found changes for VXLAN dataplane config")
	}
	changeSet = changeSet.Merge(vxlanChangeSet)

	log.Println("Detecting changes for VethPair ...")
	vethPairChangeSet, err := dpConfig.VethPair.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for VethPair: %w", err)
	}
	if vethPairChangeSet != nil && vethPairChangeSet.HasChanges() {
		log.Println("Found changes for VethPair dataplane config")
	}
	changeSet = changeSet.Merge(vethPairChangeSet)

	log.Println("Detecting changes for Bridge ...")
	bridgeChangeSet, err := dpConfig.Bridge.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for Bridge: %w", err)
	}
	if bridgeChangeSet != nil && bridgeChangeSet.HasChanges() {
		log.Println("Found changes for Bridge dataplane config")
	}
	changeSet = changeSet.Merge(bridgeChangeSet)

	log.Println("Detecting changes for Dummy ...")
	dummyChangeSet, err := dpConfig.Dummy.DetectChanges(ctx, containers)
	if err != nil {
		return nil, fmt.Errorf("failed to detect changes for Dummy: %w", err)
	}
	if dummyChangeSet != nil && dummyChangeSet.HasChanges() {
		log.Println("Found changes for Dummy dataplane config")
	}
	changeSet = changeSet.Merge(dummyChangeSet)

	return changeSet, nil
}

type InterfaceChangeSet interface {
	Apply(ctx context.Context) error
	HasUpdates() bool
	GetInterfaceName() string
	GetContainerName() *string
}

type InterfaceProvisioner interface {
	// In case the interface is not created yet, one can call `Create` to create the interface.
	Create(ctx context.Context) error

	// In case the interface is already created, one can call `DetectChanges` to detect any changes.
	// Also, a `*InterfaceChangeSet` might be nil regardless of there is error or not.
	DetectChanges(ctx context.Context) (InterfaceChangeSet, error)

	// Get the interface name for indexing and logging purposes.
	GetInterfaceName() string

	// Get the container name for indexing and logging purposes.
	GetContainerName() *string
}

type InterfaceCanceller interface {
	Cancel(ctx context.Context) error
	GetInterfaceName() string
	GetContainerName() *string
}

type OpenVPN2InterfaceCanceller struct {
	ContainerName string
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) Cancel(ctx context.Context) error {
	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker client: %w", err)
	}

	if err := cli.ContainerStop(ctx, ovpInterfaceCanceller.ContainerName, container.StopOptions{}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	return nil
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetContainerName() *string {
	return &ovpInterfaceCanceller.ContainerName
}

func (ovpInterfaceCanceller *OpenVPN2InterfaceCanceller) GetInterfaceName() string {
	return "-"
}

type StubInterfaceCanceller struct {
	ContainerName *string
	InterfaceName string
}

func (stubInterfaceCanceller *StubInterfaceCanceller) Cancel(ctx context.Context) error {
	return withNsHandle(ctx, stubInterfaceCanceller.ContainerName, func(handle *netlink.Handle) error {
		link, err := handle.LinkByName(stubInterfaceCanceller.InterfaceName)
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return fmt.Errorf("failed to get link: %w", err)
			}
			return nil
		}

		if err := handle.LinkDel(link); err != nil {
			return fmt.Errorf("failed to delete link: %w", err)
		}

		return nil
	})
}

func (stubInterfaceCanceller *StubInterfaceCanceller) GetInterfaceName() string {
	return stubInterfaceCanceller.InterfaceName
}

func (stubInterfaceCanceller *StubInterfaceCanceller) GetContainerName() *string {
	return stubInterfaceCanceller.ContainerName
}

type DataplaneChangeSet struct {
	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be added
	AddedInterfaces map[string][]InterfaceProvisioner

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be updated
	UpdatedInterfaces map[string][]InterfaceChangeSet

	// key is the container name, for default netns, the key will be '-', value is the list of interfaces to be removed
	RemovedInterfaces map[string][]InterfaceCanceller
}

func (dpChangeSet *DataplaneChangeSet) Merge(other *DataplaneChangeSet) *DataplaneChangeSet {
	if dpChangeSet == nil {
		return other
	}

	if other == nil {
		return dpChangeSet
	}

	result := new(DataplaneChangeSet)

	mergedAdded := make(map[string][]InterfaceProvisioner)
	for k, v := range dpChangeSet.AddedInterfaces {
		mergedAdded[k] = append(mergedAdded[k], v...)
	}
	for k, v := range other.AddedInterfaces {
		if curr, ok := mergedAdded[k]; ok {
			mergedAdded[k] = append(curr, v...)
		} else {
			mergedAdded[k] = v
		}
	}

	mergedUpdated := make(map[string][]InterfaceChangeSet)
	for k, v := range dpChangeSet.UpdatedInterfaces {
		mergedUpdated[k] = append(mergedUpdated[k], v...)
	}
	for k, v := range other.UpdatedInterfaces {
		if curr, ok := mergedUpdated[k]; ok {
			mergedUpdated[k] = append(curr, v...)
		} else {
			mergedUpdated[k] = v
		}
	}

	mergedRemoved := make(map[string][]InterfaceCanceller)
	for k, v := range dpChangeSet.RemovedInterfaces {
		mergedRemoved[k] = append(mergedRemoved[k], v...)
	}
	for k, v := range other.RemovedInterfaces {
		if curr, ok := mergedRemoved[k]; ok {
			mergedRemoved[k] = append(curr, v...)
		} else {
			mergedRemoved[k] = v
		}
	}

	result.AddedInterfaces = mergedAdded
	result.UpdatedInterfaces = mergedUpdated
	result.RemovedInterfaces = mergedRemoved

	return result
}

func (dpChangeSet *DataplaneChangeSet) HasChanges() bool {
	if dpChangeSet != nil {
		return len(dpChangeSet.AddedInterfaces)+len(dpChangeSet.UpdatedInterfaces)+len(dpChangeSet.RemovedInterfaces) > 0
	}

	return false
}

func getContainerDisplayName(containerName *string) string {
	if containerName != nil {
		return fmt.Sprintf("container %s", *containerName)
	}

	return "host"
}

func (dpChangeSet *DataplaneChangeSet) Apply(ctx context.Context) error {
	if dpChangeSet.HasChanges() {
		for _, removedInterface := range dpChangeSet.RemovedInterfaces {
			for _, canceller := range removedInterface {
				log.Printf("Removing interface %s in %s ...", canceller.GetInterfaceName(), getContainerDisplayName(canceller.GetContainerName()))
				if err := canceller.Cancel(ctx); err != nil {
					return fmt.Errorf("failed to cancel interface: %w", err)
				}
			}
		}

		for _, updatedInterface := range dpChangeSet.UpdatedInterfaces {
			for _, changeSet := range updatedInterface {
				if changeSet.HasUpdates() {
					log.Printf("Updating interface %s in %s ...", changeSet.GetInterfaceName(), getContainerDisplayName(changeSet.GetContainerName()))
					if err := changeSet.Apply(ctx); err != nil {
						return fmt.Errorf("failed to update interface: %w", err)
					}
				}
			}
		}

		for _, addedInterface := range dpChangeSet.AddedInterfaces {
			for _, provisioner := range addedInterface {
				log.Printf("Creating interface %s in %s ...", provisioner.GetInterfaceName(), getContainerDisplayName(provisioner.GetContainerName()))
				if err := provisioner.Create(ctx); err != nil {
					return fmt.Errorf("failed to create interface: %w", err)
				}
			}
		}
	}
	return nil
}

func (dpConfig *DataplaneConfig) Apply(ctx context.Context, containers []string) error {
	log.Println("Detecting changes for dataplane config ...")
	changeSet, err := dpConfig.DetectChanges(ctx, containers)
	if err != nil {
		return fmt.Errorf("failed to detect changes: %w", err)
	}
	if changeSet.HasChanges() {
		log.Println("Applying changes for dataplane config ...")
		if err := changeSet.Apply(ctx); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}
	}

	return nil
}

type NodeConfig struct {
	DockerContainers []DockerContainerConfig `yaml:"docker_containers,omitempty" json:"docker_containers,omitempty"`
	Controlplane     *ControlplaneConfig     `yaml:"controlplane,omitempty" json:"controlplane,omitempty"`
	Dataplane        *DataplaneConfig        `yaml:"dataplane,omitempty" json:"dataplane,omitempty"`
	Containers       []string                `yaml:"containers,omitempty" json:"containers,omitempty"`
}

func (controlPlaneConfig *ControlplaneConfig) Create(ctx context.Context) error {

	configsToApply := make([]string, 0)

	if controlPlaneConfig.OSPF != nil {
		ospfPatchPath := path.Join(controlPlaneConfig.HostPatchDir, "ospf.conf")
		ospfPatchFile, err := os.OpenFile(ospfPatchPath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to open ospf patch file: %w", err)
		}
		defer ospfPatchFile.Close()

		for _, ospfConf := range controlPlaneConfig.OSPF {
			cmds := ospfConf.ToCLICommands()
			for _, cmd := range cmds {
				ospfPatchFile.WriteString(cmd + "\n")
			}
		}
		configsToApply = append(configsToApply, path.Join(controlPlaneConfig.ContainerPatchDir, path.Base(ospfPatchPath)))
	}

	if controlPlaneConfig.BGP != nil {
		bgpPatchPath := path.Join(controlPlaneConfig.HostPatchDir, "bgp.conf")
		bgpPatchFile, err := os.OpenFile(bgpPatchPath, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %w", err)
		}
		defer bgpPatchFile.Close()

		for _, bgpConf := range controlPlaneConfig.BGP {
			cmds := bgpConf.ToCLICommands()
			for _, cmd := range cmds {
				bgpPatchFile.WriteString(cmd + "\n")
			}
		}
		configsToApply = append(configsToApply, path.Join(controlPlaneConfig.ContainerPatchDir, path.Base(bgpPatchPath)))
	}

	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}
	cont, err := findContainer(ctx, cli, *controlPlaneConfig.ContainerName)
	if err != nil {
		return fmt.Errorf("failed to find container: %w", err)
	}
	if cont == nil {
		return fmt.Errorf("container %s not found", *controlPlaneConfig.ContainerName)
	}

	if err := cli.ContainerStart(ctx, cont.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	for _, configToApply := range configsToApply {
		execOptions := container.ExecOptions{
			Cmd: []string{
				"vtysh",
				"-f",
				configToApply,
			},
		}
		exec, err := cli.ContainerExecCreate(ctx, cont.ID, execOptions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create exec: %v\n", err)
			continue
		}

		if err := cli.ContainerExecStart(ctx, exec.ID, container.ExecStartOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start exec: %v\n", err)
			continue
		}
	}

	return nil
}

type GlobalConfig struct {
	Nodes map[string]NodeConfig `yaml:"nodes" json:"nodes"`
}

func parseTag(tag string) (map[string]string, []string, string) {
	tags := make([]string, 0)

	parts := strings.Split(tag, ",")
	tagMap := make(map[string]string)
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) > 1 && kv[1] != "" {
			tagMap[kv[0]] = kv[1]
		} else {
			tagMap[kv[0]] = ""
		}
	}

	firstTag := ""
	if len(parts) > 0 {
		firstTag = parts[0]
	}

	return tagMap, tags, firstTag
}

func (ovInstPtr *OpenVPN2Instance) ToCLIArgs() []string {
	if ovInstPtr == nil {
		return nil
	}

	ovInst := *ovInstPtr

	res := make([]string, 0)

	v := reflect.ValueOf(ovInst)
	// ty := reflect.TypeOf(ovInst)
	for i := 0; i < v.NumField(); i++ {
		// Get the field tag value
		tag := v.Type().Field(i).Tag.Get(tagName)
		if tag == "" || tag == "-" {
			continue
		}

		_, _, firstTag := parseTag(tag)

		// Get the field value
		// fieldName := ty.Field(i).Name
		val := v.Field(i).Interface()

		switch typedval := val.(type) {
		case *bool:
			if typedval != nil {
				if *typedval {
					if firstTag != "" {
						res = append(res, fmt.Sprintf("--%s", firstTag))
					}
				}
			}
		case *int:
			if typedval != nil {
				res = append(res, fmt.Sprintf("--%s", firstTag))
				res = append(res, fmt.Sprintf("%v", *typedval))
			}
		case *string:

			if typedval != nil {
				res = append(res, fmt.Sprintf("--%s", firstTag))
				res = append(res, fmt.Sprintf("%v", *typedval))
			}
		case bool:
			if typedval {
				res = append(res, fmt.Sprintf("--%s", firstTag))
			}
		case int:
			res = append(res, fmt.Sprintf("--%s", firstTag))
			res = append(res, fmt.Sprintf("%v", typedval))
		case string:

			res = append(res, fmt.Sprintf("--%s", firstTag))
			res = append(res, fmt.Sprintf("%v", typedval))
		default:

			kind := v.Field(i).Kind()

			if kind == reflect.Pointer && !v.Field(i).IsNil() {
				method := v.Field(i).MethodByName("ToCLIArgs")
				if !method.IsZero() {
					res = append(res, fmt.Sprintf("--%s", firstTag))
					if retval := method.Call(nil); len(retval) > 0 {
						if retval1, ok := (retval[0].Interface()).([]string); ok {
							res = append(res, retval1...)
						}
					}
				}
			} else if !v.Field(i).IsZero() {
				res = append(res, fmt.Sprintf("--%s", firstTag))

				valType := v.Field(i).Type()

				valobj := reflect.New(valType)
				valobj.Elem().Set(v.Field(i))

				retval := valobj.MethodByName("ToCLIArgs").Call(nil)
				if len(retval) > 0 {
					if retval1, ok := (retval[0].Interface()).([]string); ok {
						res = append(res, retval1...)
					}
				}

			}
		}
	}

	return res
}

type Instance struct {
	Name   string
	Target string
}

const labelKeyService string = "service"
const labelKeyInstance string = "instance"

func (nodeConfig *NodeConfig) Up(ctx context.Context) error {
	if nodeConfig.DockerContainers != nil {
		log.Println("Setting up docker containers ...")

		for _, dockerContainer := range nodeConfig.DockerContainers {
			log.Printf("Setting up docker container %s ...", dockerContainer.ContainerName)

			if err := dockerContainer.Create(ctx); err != nil {
				return fmt.Errorf("failed to create docker container %s: %w", dockerContainer.ContainerName, err)
			}
		}
	}

	if nodeConfig.Dataplane != nil {
		log.Println("Setting up dataplane ...")
		if err := nodeConfig.Dataplane.Apply(ctx, nodeConfig.Containers); err != nil {
			return fmt.Errorf("failed to create dataplane: %w", err)
		}
	}

	if nodeConfig.Controlplane != nil {
		log.Println("Setting up controlplane ...")
		if err := nodeConfig.Controlplane.Create(ctx); err != nil {
			return fmt.Errorf("failed to create controlplane: %w", err)
		}
	}

	return nil
}

type ContainerList struct {
	containers []container.Summary
}

func (containerList *ContainerList) GetContainers() []container.Summary {
	return containerList.containers
}

func NewContainerListFromServiceName(ctx context.Context, serviceName string) (*ContainerList, error) {
	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	dockerArgs := filters.NewArgs()
	dockerArgs.Add("label", fmt.Sprintf("%s=%s", labelKeyService, serviceName))
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: dockerArgs,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return &ContainerList{containers: containers}, nil
}

func down(ctx context.Context) error {
	serviceName, err := serviceNameFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get service name from context: %w", err)
	}

	containerList, err := NewContainerListFromServiceName(ctx, serviceName)
	if err != nil {
		return fmt.Errorf("failed to get container list from service name: %w", err)
	}

	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	for _, cont := range containerList.GetContainers() {
		if err := cli.ContainerStop(ctx, cont.ID, container.StopOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop container %s: %v\n", cont.Names[0], err)
			continue
		}
		labelsStr := ""
		if cont.Labels != nil {
			v, err := json.Marshal(cont.Labels)
			if err != nil {
				log.Fatalf("failed to marshal labels for %s: %v", cont.Names[0], err)
			}
			labelsStr = string(v)
		}
		log.Printf("Container %s %s is stopped", cont.Names[0], labelsStr)
	}

	return nil
}

const tagName string = "openvpn2"

// getGlobalConfig reads configuration from either a file, stdin, or HTTP(S) endpoint
// path: file path, "-" for stdin, or HTTP(S) URL
// config: pointer to GlobalConfig struct to populate
// tlsConfig: TLS configuration for HTTPS requests (can be nil for default)
func getGlobalConfig(cmd *UpCmd, config *GlobalConfig) error {
	var reader io.Reader
	var err error

	path := cmd.Config

	if path == "-" {
		log.Println("Reading configuration from stdin ...")
		// Read from stdin
		reader = os.Stdin
	} else if strings.HasPrefix(path, "https://") {
		log.Printf("Reading configuration from HTTPS endpoint %s ...", path)

		tlsConfig, err := getTLSConfig(cmd.TLSTrustedCACert, cmd.TLSClientCert, cmd.TLSClientKey)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}

		// Read from HTTPS endpoint
		reader, err = fetchHTTPConfig(path, tlsConfig, cmd.HTTPBasicAuthUsername, cmd.HTTPBasicAuthPassword)
		if err != nil {
			return fmt.Errorf("failed to fetch HTTPS config from '%s': %w", path, err)
		}
	} else if strings.HasPrefix(path, "http://") {
		log.Printf("Reading configuration from HTTP endpoint %s ...", path)

		// Read from HTTP endpoint
		reader, err = fetchHTTPConfig(path, nil, cmd.HTTPBasicAuthUsername, cmd.HTTPBasicAuthPassword)
		if err != nil {
			return fmt.Errorf("failed to fetch HTTP config from '%s': %w", path, err)
		}
	} else {
		log.Printf("Reading configuration from file %s ...", path)

		// Read from file
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open config file '%s': %w", path, err)
		}
		defer file.Close()
		reader = file
	}

	// Parse YAML configuration
	if err := yaml.NewDecoder(reader).Decode(config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	return nil
}

// fetchHTTPConfig fetches configuration from an HTTP(S) endpoint
func fetchHTTPConfig(url string, tlsConfig *tls.Config, username, password string) (io.Reader, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	if tlsConfig != nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	request.Header.Set("Accept", "application/yaml")

	// Add basic authentication if credentials are provided
	if username != "" && password != "" {
		request.SetBasicAuth(username, password)
	}

	// Make HTTP request
	resp, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP request failed with status %d: %s", resp.StatusCode, resp.Status)
	}

	// Read response body into memory
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return strings.NewReader(string(body)), nil
}

// getTLSConfig creates a TLS configuration from the provided certificate files
func getTLSConfig(caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	// If no TLS parameters are provided, return nil (use default TLS config)
	if caCertPath == "" && clientCertPath == "" && clientKeyPath == "" {
		return nil, nil
	}

	config := &tls.Config{}

	// Load CA certificate if provided
	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate from '%s': %w", caCertPath, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from '%s'", caCertPath)
		}
		config.RootCAs = caCertPool
	}

	// Load client certificate and key if both are provided
	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate pair (cert: '%s', key: '%s'): %w", clientCertPath, clientKeyPath, err)
		}
		config.Certificates = []tls.Certificate{cert}
	} else if clientCertPath != "" || clientKeyPath != "" {
		// If only one of client cert or key is provided, that's an error
		return nil, fmt.Errorf("both client certificate and key must be provided together")
	}

	return config, nil
}

// CLI structure for Kong
type CLI struct {
	Up   UpCmd   `cmd:"" help:"Start the service with the specified configuration"`
	Down DownCmd `cmd:"" help:"Stop all containers associated with the service"`
}

type UpCmd struct {
	Config                string `required:"" help:"Path to the configuration file" type:"path"`
	ServiceName           string `required:"" help:"Name of the service" short:"s"`
	Node                  string `required:"" help:"Name of the node to start" short:"n"`
	TLSTrustedCACert      string `help:"Path to trusted CA certificate file for TLS" type:"path"`
	TLSClientCert         string `help:"Path to client certificate file for TLS" type:"path"`
	TLSClientKey          string `help:"Path to client private key file for TLS" type:"path"`
	HTTPBasicAuthUsername string `help:"Username for HTTP basic authentication"`
	HTTPBasicAuthPassword string `help:"Password for HTTP basic authentication"`
}

type DownCmd struct {
	ServiceName string `required:"" help:"Name of the service" short:"s"`
}

// Run method for UpCmd
func (cmd *UpCmd) Run() error {
	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Set up context with service name and docker client
	ctx = setServiceNameInCtx(ctx, cmd.ServiceName)
	ctx = setDockerCliInCtx(ctx, cli)

	// Read and parse the configuration
	globalConfig := new(GlobalConfig)
	if err := getGlobalConfig(cmd, globalConfig); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get the specified node configuration
	nodeConfig, ok := globalConfig.Nodes[cmd.Node]
	if !ok {
		return fmt.Errorf("node '%s' not found in configuration", cmd.Node)
	}

	// Start the service
	log.Printf("Setting up service %s on node %s ...", cmd.ServiceName, cmd.Node)
	if err := nodeConfig.Up(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// Run method for DownCmd
func (cmd *DownCmd) Run() error {
	ctx := context.Background()

	// Initialize Docker client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer cli.Close()

	// Set up context with service name and docker client
	ctx = setServiceNameInCtx(ctx, cmd.ServiceName)
	ctx = setDockerCliInCtx(ctx, cli)

	// Stop all containers associated with the service
	if err := down(ctx); err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	log.Printf("Service '%s' stopped successfully\n", cmd.ServiceName)
	return nil
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)
	err := ctx.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
