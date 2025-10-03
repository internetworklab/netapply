package container_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/client"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgfrrcontainer "github.com/internetworklab/netapply/pkg/frr/container"
	pkgfrrvtyshcontainer "github.com/internetworklab/netapply/pkg/frr/vtysh/container"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
)

// To test, simply invoke `go test -v --run TestContainerVtyshConfigWriter ./pkg/frr/vtysh/container`

func TestContainerVtyshConfigWriter(t *testing.T) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Fatalf("failed to create docker client: %v", err)
	}
	defer cli.Close()

	ctx = pkgutils.SetDockerCliInCtx(ctx, cli)

	now := time.Now()
	testFRRContainerName := fmt.Sprintf("frr-%d", now.Unix())
	t.Logf("Using test FRR container name %s", testFRRContainerName)

	containerConfig := pkgfrrcontainer.DefaultFRRContainerConfig()
	containerConfig.ContainerName = testFRRContainerName

	t.Logf("Starting tester FRR container %s", testFRRContainerName)

	err = containerConfig.Apply(ctx)
	if err != nil {
		t.Fatalf("failed to apply FRR container config: %v", err)
	}
	defer func() {
		t.Logf("Cleaning up the test FRR container %s", testFRRContainerName)
		err = pkgdocker.StopAndRemoveContainer(ctx, testFRRContainerName)
		if err != nil {
			t.Fatalf("failed to stop and remove FRR container: %v", err)
		}
	}()

	t.Logf("Wait for 5 seconds for the FRR container to start up")
	time.Sleep(5 * time.Second)

	cont, err := pkgdocker.FindContainer(ctx, cli, testFRRContainerName)
	if err != nil {
		t.Fatalf("failed to find FRR container: %v", err)
	}
	if cont == nil {
		t.Fatalf("FRR container %s not found", testFRRContainerName)
	}

	t.Logf("Found FRR container %s, container id: %s, image: %s", testFRRContainerName, cont.ID, cont.Image)

	containerName := testFRRContainerName
	vrfName := "v1"
	routerID := "1.2.3.4"
	commands := []string{
		"configure",
		"router ospf vrf " + vrfName,
		"ospf router-id " + routerID,
		"exit",
	}
	vtyshPath := "vtysh"

	writer, err := pkgfrrvtyshcontainer.NewContainerVtyshConfigWriter(ctx, containerName, &vtyshPath)
	if err != nil {
		t.Fatalf("failed to create container vtysh config writer: %v", err)
	}
	defer writer.Close()

	t.Logf("Writing commands to container vtysh to configure OSPF router in vrf %s with router ID %s", vrfName, routerID)
	if err := writer.WriteCommands(ctx, commands); err != nil {
		t.Fatalf("failed to write commands: %v", err)
	}

	t.Logf("Checking if the configuration is applied")
	outBytes, err := writer.ExecuteCommands(ctx, []string{"show running-config"})
	if err != nil {
		t.Fatalf("failed to execute command to query the running configuration: %v", err)
	}
	t.Logf("Running configuration: \n")
	runningConfigS := string(outBytes)
	for _, line := range strings.Split(runningConfigS, "\n") {
		t.Log(line)
	}

	finds := []string{
		"router ospf vrf " + vrfName,
		"ospf router-id " + routerID,
	}
	for _, find := range finds {
		t.Logf("Finding %s in the running configuration", find)
		if !strings.Contains(runningConfigS, find) {
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
