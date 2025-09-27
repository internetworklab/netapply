package openvpn2_test

import (
	"os"
	"testing"

	"example.com/connector/pkg/openvpn2"
	"gopkg.in/yaml.v3"
)

func TestMarshal(t *testing.T) {

	filePath := "examples/openvpn.yaml"
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open file: %v", err)
	}
	defer file.Close()

	ovpInst := new(openvpn2.OpenVPN2Instance)
	yaml.NewDecoder(file).Decode(ovpInst)

	openvpn2CLIArgs, err := openvpn2.Marshal(ovpInst)
	if err != nil {
		t.Fatalf("failed to marshal openvpn2 instance into CLI arguments: %v", err)
	}

	t.Logf("openvpn2CLIArgs: %v", openvpn2CLIArgs)
	// cmd = append(cmd, openvpn2CLIArgs...)
}
