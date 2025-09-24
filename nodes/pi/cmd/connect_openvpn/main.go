package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
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

type CtxKey string

const ctxKeyDockerCli CtxKey = "docker_cli"

func dockerCliFromCtx(ctx context.Context) (*client.Client, error) {
	cli, ok := ctx.Value(ctxKeyDockerCli).(*client.Client)
	if !ok {
		return nil, fmt.Errorf("docker cli is not set in context")
	}

	return cli, nil
}

func setDockerCliInCtx(ctx context.Context, cli *client.Client) context.Context {
	return context.WithValue(ctx, ctxKeyDockerCli, cli)
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

func (ovpInst *OpenVPN2Instance) Start(ctx context.Context, servicename string) error {

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

	containerConfig := &container.Config{
		Image:     ovpInst.DockerContainer.Image,
		Cmd:       cmd,
		Tty:       true,
		OpenStdin: true,
		Labels: map[string]string{
			labelKeyService:  servicename,
			labelKeyInstance: ovpInst.Name,
		},
	}

	networkConfig := &network.NetworkingConfig{}
	if ovpInst.DockerContainer.Networks != nil {
		networkConfig.EndpointsConfig = make(map[string]*network.EndpointSettings)
		for _, networkName := range ovpInst.DockerContainer.Networks {
			networkConfig.EndpointsConfig[networkName] = &network.EndpointSettings{}
		}
	}

	hostConfig := &container.HostConfig{}
	if ovpInst.DockerContainer.AutoRemove != nil {
		hostConfig.AutoRemove = *ovpInst.DockerContainer.AutoRemove
	}

	if ovpInst.DockerContainer.Capabilities != nil {
		hostConfig.CapAdd = strslice.StrSlice(ovpInst.DockerContainer.Capabilities)
	}

	if ovpInst.DockerContainer.Hostname != nil {
		containerConfig.Hostname = *ovpInst.DockerContainer.Hostname
	}

	if ovpInst.DockerContainer.Ports != nil {
		portMaps := make(nat.PortMap, 0)
		for containerPort, hostPortMappings := range ovpInst.DockerContainer.Ports {
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

	if ovpInst.DockerContainer.Volumes != nil {
		volumeMounts := make([]mount.Mount, 0)
		for _, volumeMount := range ovpInst.DockerContainer.Volumes {
			volumeMounts = append(volumeMounts, mount.Mount{
				Type:   volumeMount.Type,
				Source: resolvePath(volumeMount.Source),
				Target: volumeMount.Target,
			})
		}
		hostConfig.Mounts = volumeMounts
	}

	if ovpInst.DockerContainer.Devices != nil {
		deviceMounts := make([]container.DeviceMapping, 0)
		for _, deviceMount := range ovpInst.DockerContainer.Devices {
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

const (
	OVTagFlagEmptyKey string = "emptykey"
)

type OSPFInterfaceConfig struct {
	Name    string  `yaml:"name" json:"name"`
	Area    string  `yaml:"area" json:"area"`
	Passive *bool   `yaml:"passive" json:"passive"`
	Network *string `yaml:"network" json:"network"`
}

type OSPFConfig struct {
	// Currently only 'default' vrf is supported
	VRF        string                `yaml:"vrf" json:"vrf"`
	RouterID   string                `yaml:"router_id" json:"router_id"`
	Interfaces []OSPFInterfaceConfig `yaml:"interfaces" json:"interfaces"`
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
	cmds = append(cmds, "configure")
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
	// Container name is the name of the container that hosts the FRR daemon
	ContainerName string       `yaml:"container_name" json:"container_name"`
	OSPF          []OSPFConfig `yaml:"ospf,omitempty" json:"ospf,omitempty"`
	BGP           []BGPConfig  `yaml:"bgp,omitempty" json:"bgp,omitempty"`
}

type DummyConfig struct {
	Name string  `yaml:"name" json:"name"`
	CIDR *string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
}

type VirtualInterfaceConfig struct {
	Dummy []DummyConfig `yaml:"dummy,omitempty" json:"dummy,omitempty"`
}

type WireGuardPeerConfig struct {
	PublicKey  string   `yaml:"publickey" json:"publickey"`
	Endpoint   string   `yaml:"endpoint" json:"endpoint"`
	AllowedIPs []string `yaml:"allowedips,omitempty" json:"allowedips,omitempty"`
}

type WireGuardAddressConfig struct {
	Peer  *string `yaml:"peer,omitempty" json:"peer,omitempty"`
	Local *string `yaml:"local,omitempty" json:"local,omitempty"`
	CIDR  *string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
}

type WireGuardConfig struct {
	Name       string                   `yaml:"name" json:"name"`
	PrivateKey string                   `yaml:"privatekey" json:"privatekey"`
	Peers      []WireGuardPeerConfig    `yaml:"peers,omitempty" json:"peers,omitempty"`
	Addresses  []WireGuardAddressConfig `yaml:"addresses,omitempty" json:"addresses,omitempty"`
}

type ContainerDockerConfig struct {
	Name string `yaml:"name" json:"name"`
}

type ContainerConfig struct {
	Docker ContainerDockerConfig `yaml:"docker,omitempty" json:"docker,omitempty"`
}

type VXLANConfig struct {
	Name       string           `yaml:"name" json:"name"`
	VXLANID    int              `yaml:"vxlan_id" json:"vxlan_id"`
	LocalIP    *string          `yaml:"local_ip,omitempty" json:"local_ip,omitempty"`
	MTU        *int             `yaml:"mtu,omitempty" json:"mtu,omitempty"`
	Nolearning *bool            `yaml:"nolearning,omitempty" json:"nolearning,omitempty"`
	Container  *ContainerConfig `yaml:"container,omitempty" json:"container,omitempty"`
}

type DataplaneConfig struct {
	OpenVPN   []OpenVPN2Instance `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
	WireGuard []WireGuardConfig  `yaml:"wireguard,omitempty" json:"wireguard,omitempty"`
	VXLAN     []VXLANConfig      `yaml:"vxlan,omitempty" json:"vxlan,omitempty"`
}

type NodeConfig struct {
	Controlplane     *ControlplaneConfig     `yaml:"controlplane,omitempty" json:"controlplane,omitempty"`
	Dataplane        *DataplaneConfig        `yaml:"dataplane,omitempty" json:"dataplane,omitempty"`
	VirtualInterface *VirtualInterfaceConfig `yaml:"virtual_interface,omitempty" json:"virtual_interface,omitempty"`
	DockerContainers []DockerContainerConfig `yaml:"docker_containers,omitempty" json:"docker_containers,omitempty"`
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

func up(ctx context.Context, servicename string, nodeConfig *NodeConfig) error {
	if nodeConfig.Dataplane != nil {
		for _, ovpInst := range nodeConfig.Dataplane.OpenVPN {
			if err := ovpInst.Start(ctx, servicename); err != nil {
				fmt.Fprintf(os.Stderr, "failed to start openvpn for %s: %v\n", ovpInst.Name, err)
				continue
			}
			log.Println("Container is started for", ovpInst.Name)
		}
	}

	return nil
}

func down(ctx context.Context, servicename string) error {
	cli, err := dockerCliFromCtx(ctx)
	if err != nil {
		return fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	dockerArgs := filters.NewArgs()
	dockerArgs.Add("label", fmt.Sprintf("%s=%s", labelKeyService, servicename))
	containers, err := cli.ContainerList(ctx, container.ListOptions{
		Filters: dockerArgs,
	})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	for _, cont := range containers {
		if err := cli.ContainerStop(context.Background(), cont.ID, container.StopOptions{}); err != nil {
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

var (
	command        string
	nodeName       string
	servicename    string
	configFilePath string
)

func main() {
	ctx := context.Background()

	flag.Parse()

	if command == "" {
		panic("command --command is required")
	}
	if nodeName == "" {
		panic("node name --node is required")
	}
	if servicename == "" {
		panic("service name --service is required")
	}
	if configFilePath == "" {
		panic("config file path --config is required")
	}

	configFile, err := os.Open(configFilePath)
	if err != nil {
		panic(err)
	}
	defer configFile.Close()

	globalConfig := new(GlobalConfig)
	if err := yaml.NewDecoder(configFile).Decode(globalConfig); err != nil {
		panic(err)
	}

	nodeConfig, ok := globalConfig.Nodes[nodeName]
	if !ok {
		panic("node config not found")
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	defer cli.Close()

	switch command {
	case "up":
		err = up(setDockerCliInCtx(ctx, cli), servicename, &nodeConfig)
	case "down":
		err = down(setDockerCliInCtx(ctx, cli), servicename)
	default:
		panic("command is unknown")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to %s: %v\n", command, err)
		os.Exit(1)
	}
}

func init() {
	flag.StringVar(&command, "command", "up", "command to run")
	flag.StringVar(&nodeName, "node", "", "node name")
	flag.StringVar(&servicename, "service", "openvpn", "service name")
	flag.StringVar(&configFilePath, "config", "./config.yaml", "config file path")
}
