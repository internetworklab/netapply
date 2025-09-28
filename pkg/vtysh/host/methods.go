package host

import (
	"context"
	"fmt"
	"os/exec"
)

func NewHostVtyshConfigWriter(p *string) *HostVtyshConfigWriter {
	writer := &HostVtyshConfigWriter{
		vtyshPath: DefaultVtyshPath,
	}

	if p != nil {
		writer.vtyshPath = *p
	}

	return writer
}

func (writer *HostVtyshConfigWriter) WriteCommands(ctx context.Context, commands []string) error {
	// Todo: implement this
	return nil
}

// Equivilent to `vtysh -c "command"`
func (writer *HostVtyshConfigWriter) ExecuteCommand(command string) ([]byte, error) {
	stdout, err := exec.Command(writer.vtyshPath, "-c", command).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %v", err)
	}

	return stdout, nil
}
