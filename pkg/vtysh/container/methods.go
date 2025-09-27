package container

import "context"

func NewContainerVtyshConfigWriter(containerName string) *ContainerVtyshConfigWriter {
	return &ContainerVtyshConfigWriter{
		containerName: containerName,
	}
}

func (writer *ContainerVtyshConfigWriter) WriteCommands(ctx context.Context, commands []string) error {
	// Create docker exec here, so the the entire ContainerVtyshConfigWriter struct
	//  doesn't have to be closed after used.

	// Todo: implement this
	return nil
}
