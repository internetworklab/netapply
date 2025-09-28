package container

import (
	"context"
	"fmt"

	pkgdocker "example.com/connector/pkg/docker"
	pkgutils "example.com/connector/pkg/utils"
	dockercontainer "github.com/docker/docker/api/types/container"
)

func NewContainerVtyshConfigWriter(ctx context.Context, containerName string, vtyshPath *string) (*ContainerVtyshConfigWriter, error) {
	w := &ContainerVtyshConfigWriter{
		containerName: containerName,
		vtyshPath:     vtyshPath,
		execID:        "",
	}
	if w.vtyshPath == nil {
		p := DefaultVtyshPath
		w.vtyshPath = &p
	}

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	contSummary, err := pkgdocker.FindContainer(ctx, cli, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to find container: %w", err)
	}

	execResp, err := cli.ContainerExecCreate(ctx, contSummary.ID, dockercontainer.ExecOptions{
		Cmd:         []string{*w.vtyshPath},
		AttachStdin: true,
		Tty:         true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %v", err)
	}

	w.execID = execResp.ID

	attachResp, err := cli.ContainerExecAttach(ctx, w.execID, dockercontainer.ExecAttachOptions{
		Tty: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %v", err)
	}

	w.dockerIO = &attachResp

	err = cli.ContainerExecStart(ctx, w.execID, dockercontainer.ExecStartOptions{
		Tty: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start exec: %v", err)
	}

	return w, nil
}

func (writer *ContainerVtyshConfigWriter) WriteCommands(ctx context.Context, commands []string) error {
	for _, command := range commands {
		_, err := writer.dockerIO.Conn.Write([]byte(command + "\n"))
		if err != nil {
			return fmt.Errorf("failed to write command: %w", err)
		}
	}
	return nil
}

func (writer *ContainerVtyshConfigWriter) Write(p []byte) (n int, err error) {
	return writer.dockerIO.Conn.Write(p)
}

func (writer *ContainerVtyshConfigWriter) Close() error {
	if writer.dockerIO != nil {
		writer.dockerIO.Close()
	}
	return nil
}
