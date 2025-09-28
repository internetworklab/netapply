package host_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	pkgfrrvtyshhost "example.com/connector/pkg/frr/vtysh/host"
)

func TestHostVtyshConfigWriter(t *testing.T) {
	writer := pkgfrrvtyshhost.NewHostVtyshConfigWriter(nil)
	defer writer.Close()

	vrfName := "v1"
	routerID := "1.2.3.4"

	t.Logf("Writing commands to host vtysh to configure OSPF router in vrf %s with router ID %s", vrfName, routerID)
	ctx := context.Background()
	if err := writer.WriteCommands(ctx, []string{
		"configure",
		"router ospf vrf " + vrfName,
		"ospf router-id " + routerID,
		"exit",
	}); err != nil {
		t.Fatalf("failed to write commands: %v", err)
	}

	t.Logf("Checking if the configuration is applied")
	outBytes, err := writer.ExecuteCommand("show running-config")
	if err != nil {
		t.Fatalf("failed to execute command to query the running configuration: %v", err)
	}

	finds := []string{
		"router ospf vrf " + vrfName,
		"ospf router-id " + routerID,
	}
	for _, find := range finds {
		t.Logf("Finding %s in the running configuration", find)
		if !strings.Contains(string(outBytes), find) {
			t.Fatalf("failed to find %s in the running configuration", find)
		}
		t.Logf("Found %s in the running configuration", find)
	}

	t.Logf("Cleaning up the test configuration")
	cleanUpCMD := []string{
		"configure",
		fmt.Sprintf("no router ospf vrf %s", vrfName),
	}
	if err := writer.WriteCommands(ctx, cleanUpCMD); err != nil {
		t.Fatalf("failed to write commands to cancel the test configuration that just applied: %v", err)
	}
}
