package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
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
	CertFile            string                     `openvpn2:"cert-file" yaml:"cert_file"`
	KeyFile             string                     `openvpn2:"key-file" yaml:"key_file"`
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
}

const (
	OVTagFlagEmptyKey string = "emptykey"
)

type ControlplaneConfig struct {
	OSPF interface{} `yaml:"ospf,omitempty" json:"ospf,omitempty"`
	BGP  interface{} `yaml:"bgp,omitempty" json:"bgp,omitempty"`
}

type DataplaneConfig struct {
	OpenVPN []OpenVPN2Instance `yaml:"openvpn,omitempty" json:"openvpn,omitempty"`
}

type NodeConfig struct {
	Controlplane ControlplaneConfig `yaml:"controlplane,omitempty" json:"controlplane,omitempty"`
	Dataplane    DataplaneConfig    `yaml:"dataplane,omitempty" json:"dataplane,omitempty"`
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

func getContainerName(service string, instance string) string {
	return fmt.Sprintf("%s-%s", service, instance)
}

const servicename string = "ping"

const labelKeyService string = "service"
const labelKeyInstance string = "instance"
const labelKeyTarget string = "target"

func startPing(cli *client.Client, instance *Instance, imagename string) error {
	ctx := context.Background()
	instancename := instance.Name
	containername := getContainerName(servicename, instancename)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:     imagename,
		Cmd:       []string{"ping", instance.Target},
		Tty:       true,
		OpenStdin: true,
		Labels: map[string]string{
			labelKeyService:  servicename,
			labelKeyInstance: instancename,
			labelKeyTarget:   instance.Target,
		},
	}, &container.HostConfig{
		AutoRemove: true,
	}, nil, nil, containername)
	if err != nil {
		return fmt.Errorf("failed to create container for %s: %w", instance.Name, err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return fmt.Errorf("failed to start container for %s: %w", instance.Name, err)
	}

	return nil
}

func up(servicename string, cli *client.Client) error {

	imgname := "busybox:latest"
	pingInstances := []Instance{
		{Name: "loopback", Target: "127.0.0.1"},
		{Name: "loopback6", Target: "::1"},
		{Name: "alidns1", Target: "223.5.5.5"},
		{Name: "alidns2", Target: "223.6.6.6"},
	}
	ctx := context.Background()
	log.Println("Pulling image", imgname)
	reader, err := cli.ImagePull(ctx, imgname, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}

	defer reader.Close()

	// cli.ImagePull is asynchronous.
	// The reader needs to be read completely for the pull operation to complete.
	// If stdout is not required, consider using io.Discard instead of os.Stdout.
	io.Copy(os.Stdout, reader)

	log.Printf("Starting %s containers", servicename)
	for _, instance := range pingInstances {
		if err := startPing(cli, &instance, imgname); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start ping for %s: %v\n", instance.Name, err)
		}
		log.Println("Container is started for", instance.Name)
	}

	return nil
}

func down(servicename string, cli *client.Client) error {
	dockerArgs := filters.NewArgs()
	dockerArgs.Add("label", fmt.Sprintf("%s=%s", labelKeyService, servicename))
	containers, err := cli.ContainerList(context.Background(), container.ListOptions{
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

func main() {

	configFile, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer configFile.Close()

	globalConfig := new(GlobalConfig)
	if err := yaml.NewDecoder(configFile).Decode(globalConfig); err != nil {
		panic(err)
	}

	cliArgs := globalConfig.Nodes["pi"].Dataplane.OpenVPN[0].ToCLIArgs()
	for idx, arg := range cliArgs {
		fmt.Printf("[%d] %s\n", idx, arg)
	}

	return

	if len(os.Args) > 1 {
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			panic(err)
		}
		defer cli.Close()

		command := os.Args[1]
		switch command {
		case "up":
			err = up(servicename, cli)
		case "down":
			err = down(servicename, cli)
		default:
			panic("command in os.Args[1] is unknown")
		}

		if err != nil {
			panic(err)
		}
	} else {
		panic("command in os.Args[1] is required")
	}
}
