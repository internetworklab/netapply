package vtysh

import "context"

type VtyshConfigWriter interface {
	WriteCommands(ctx context.Context, commands []string) error
}
