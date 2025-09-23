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
)

type OpenVPN2Role string

const (
	OpenVPN2RoleClient OpenVPN2Role = "client"
	OpenVPN2RoleServer OpenVPN2Role = "server"
)

type OpenVPN2HttpProxy struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type OpenVPN2Proto string

const (
	OpenVPN2ProtoTCP       OpenVPN2Proto = "tcp"
	OpenVPN2ProtoUDP       OpenVPN2Proto = "udp"
	OpenVPN2ProtoTCPServer OpenVPN2Proto = "tcp-server"
	OpenVPN2ProtoUDPServer OpenVPN2Proto = "udp-server"
	OpenVPN2ProtoTCPClient OpenVPN2Proto = "tcp-client"
	OpenVPN2ProtoUDPClient OpenVPN2Proto = "udp-client"
)

type OpenVPN2Topology string

const (
	OpenVPN2TopologySubnet OpenVPN2Topology = "subnet"
	OpenVPN2TopologyNet30  OpenVPN2Topology = "net30"
)

type OpenVPN2KeepaliveConfig struct {
	IntervalSecs int `json:"interval_secs"`
	PatienceSecs int `json:"patience_secs"`
}

type OpenVPN2RemoteConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type OpenVPN2RemoteTLSCertType string

const (
	OpenVPN2RemoteTLSCertTypeServer OpenVPN2RemoteTLSCertType = "server"
	OpenVPN2RemoteTLSCertTypeClient OpenVPN2RemoteTLSCertType = "client"
)

type OpenVPN2Instance struct {
	Name               string                     `openvpn2:"-"`
	Client             *bool                      `openvpn2:"client"`
	Server             *bool                      `openvpn2:"server"`
	Port               *int                       `openvpn2:"port"`
	Dev                string                     `openvpn2:"dev"`
	Proto              OpenVPN2Proto              `openvpn2:"proto"`
	Remote             *OpenVPN2RemoteConfig      `openvpn2:"remote"`
	NoBind             *bool                      `openvpn2:"no-bind"`
	PersistTun         *bool                      `openvpn2:"persist-tun"`
	HttpProxy          *OpenVPN2HttpProxy         `openvpn2:"http-proxy"`
	CertFile           string                     `openvpn2:"cert-file"`
	KeyFile            string                     `openvpn2:"key-file"`
	DHPEMFile          *string                    `openvpn2:"dh"`
	PeerFingerprint    string                     `openvpn2:"peer-fingerprint"`
	RemoteCertTls      *OpenVPN2RemoteTLSCertType `openvpn2:"remote-cert-tls"`
	Verb               *int                       `openvpn2:"verb"`
	TLSServer          *bool                      `openvpn2:"tls-server"`
	DataCiphers        *string                    `openvpn2:"data-ciphers"`
	Topology           *OpenVPN2Topology          `openvpn2:"topology"`
	ServerBridge       *bool                      `openvpn2:"server-bridge"`
	ClientToClient     *bool                      `openvpn2:"client-to-client"`
	KeepaliveIntvSecs  *OpenVPN2KeepaliveConfig   `openvpn2:"keepalive"`
	StatusFile         *string                    `openvpn2:"status"`
	ExplicitExitNotify *bool                      `openvpn2:"explicit-exit-notify"`
}

const (
	OVTagFlagEmptyKey string = "emptykey"
)

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
			res = append(res, fmt.Sprintf("--%s", firstTag))
			res = append(res, "<todo>")
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

	port := 1010
	noBind := true
	persistTun := true
	dhPEMFile := "/path/to/dh.pem"
	remoteTLSCertType := OpenVPN2RemoteTLSCertTypeServer
	verb := 3
	tlsServer := true
	intv := OpenVPN2KeepaliveConfig{
		IntervalSecs: 10,
		PatienceSecs: 120,
	}
	statusFile := "openvpn-status.log"
	explicitExitNotify := true
	isclient := true
	ovInst := OpenVPN2Instance{
		Name:   "name1",
		Client: &isclient,
		Port:   &port,
		Dev:    "tap0",
		Proto:  OpenVPN2ProtoTCP,
		Remote: &OpenVPN2RemoteConfig{
			Host: "148.135.56.215",
			Port: 21194,
		},
		NoBind:             &noBind,
		PersistTun:         &persistTun,
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		DHPEMFile:          &dhPEMFile,
		PeerFingerprint:    "06:00:DD:D5:77:82:A0:E6:E5:5F:C4:A0:F5:D3:5A:98:23:6E:E5:DC:86:D3:AB:60:9F:01:1B:97:D4:A6:60:BE",
		RemoteCertTls:      &remoteTLSCertType,
		Verb:               &verb,
		TLSServer:          &tlsServer,
		KeepaliveIntvSecs:  &intv,
		StatusFile:         &statusFile,
		ExplicitExitNotify: &explicitExitNotify,
	}

	res := ovInst.ToCLIArgs()
	for idx, x := range res {
		fmt.Printf("[%d]: %s\n", idx, x)
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
