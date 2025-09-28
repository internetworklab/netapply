package daemons

import (
	"context"
	"testing"
)

// To test, run: go test -v ./pkg/frr/daemons from project root

func TestDefaultFRREnabledDaemonsConfig(t *testing.T) {
	cfg := DefaultFRRDaemonsConfig()
	ctx := context.Background()
	lines, err := cfg.ToConfigLines(ctx)
	if err != nil {
		t.Fatalf("failed to convert enable daemons config to config lines: %v", err)
	}
	for i, line := range lines {
		t.Logf("[%d] %s", i, line)
	}
}
