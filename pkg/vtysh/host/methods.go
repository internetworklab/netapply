package host

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
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

	cliArgs := make([]string, 0)
	cmdArgs := make([]string, 0)

	for _, c := range commands {
		trimedC := strings.TrimSpace(c)
		if len(trimedC) > 0 {
			cmdArgs = append(cmdArgs, "-c", trimedC)
		}
	}

	if len(cmdArgs) == 0 {
		return fmt.Errorf("no commands to execute")
	}

	cliArgs = append(cliArgs, cmdArgs...)

	_, err := exec.Command(writer.vtyshPath, cliArgs...).Output()
	if err != nil {
		return fmt.Errorf("failed to execute commands: %v", err)
	}

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

func (writer *HostVtyshConfigWriter) Close() error {
	return nil
}
