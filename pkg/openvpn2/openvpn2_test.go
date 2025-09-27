package openvpn2_test

// In project's root, run:
// go test -v ./pkg/openvpn2
// `-v` is for printing out the logs generated from `t.Logf` during the test

import (
	"strings"
	"testing"

	"example.com/connector/pkg/openvpn2"
	"gopkg.in/yaml.v3"
)

func TestMarshal(t *testing.T) {

	openvpn2YAML := `
name: pi
client: true
dev: tap0
proto: tcp
remote:
  host: "148.135.56.215"
  port: 21194
resolv_retry: infinite
nobind: true
http_proxy:
  host: "ss"
  port: 8080
cert_file: /etc/openvpn/certs/client-cert.pem
key_file: /etc/openvpn/certs/client-key.pem
peer_fingerprint: "A6:79:F7:4A:0C:A6:4A:D1:6F:85:2E:25:8F:D8:C2:2A:62:4F:61:FB:4C:5C:38:11:5E:4E:39:51:93:11:DD:DF"
remote_cert_tls: server
verb: 3
keepalive:
  interval_secs: 30
  patience_secs: 120
up_cmd: /up-wrapper.sh
script_security_level: 3
executable_path: "openvpn"
`

	openvpn2YAML = strings.TrimSpace(openvpn2YAML)

	ovpInst := new(openvpn2.OpenVPN2Instance)
	if err := yaml.Unmarshal([]byte(openvpn2YAML), ovpInst); err != nil {
		t.Fatalf("failed to unmarshal openvpn2 instance: %v", err)
	}

	openvpn2CLIArgs, err := openvpn2.Marshal(ovpInst)
	if err != nil {
		t.Fatalf("failed to marshal openvpn2 instance into CLI arguments: %v\n", err)
	}

	if len(openvpn2CLIArgs) == 0 {
		t.Fatalf("failed to marshal openvpn2 instance into CLI arguments: %v\n", err)
	}

	for i, arg := range openvpn2CLIArgs {
		t.Logf("openvpn2CLIArgs[%d]: %s", i, arg)
	}
}
