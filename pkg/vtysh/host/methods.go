package host

import "context"

func NewHostVtyshConfigWriter() *HostVtyshConfigWriter {
	return &HostVtyshConfigWriter{
		hostCmd: defaultHostCmd,
	}
}

func (writer *HostVtyshConfigWriter) WriteCommands(ctx context.Context, commands []string) error {
	// Todo: implement this
	return nil
}
