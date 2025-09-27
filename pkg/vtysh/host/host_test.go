package host_test

import (
	"context"
	"testing"

	host "example.com/connector/pkg/vtysh/host"
)

func TestHostVtyshConfigWriter(t *testing.T) {
	writer := host.NewHostVtyshConfigWriter()
	ctx := context.Background()
	writer.WriteCommands(ctx, []string{"show ip route"})
}
