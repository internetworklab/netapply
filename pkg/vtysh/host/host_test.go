package host_test

import (
	"context"
	"testing"

	host "example.com/connector/pkg/vtysh/host"
)

func TestHostVtyshConfigWriter(t *testing.T) {
	writer := host.NewHostVtyshConfigWriter(nil)
	defer writer.Close()

	ctx := context.Background()
	if err := writer.WriteCommands(ctx, []string{
		"configure",
		"router ospf vrf v1",
		"ospf router-id 1.2.3.4",
		"exit",
	}); err != nil {
		t.Fatalf("failed to write commands: %v", err)
	}

}
