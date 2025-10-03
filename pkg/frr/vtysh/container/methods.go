package container

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	dockercontainer "github.com/docker/docker/api/types/container"
	pkgdocker "github.com/internetworklab/netapply/pkg/docker"
	pkgutils "github.com/internetworklab/netapply/pkg/utils"
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

	if contSummary == nil {
		return nil, fmt.Errorf("container %s not found", containerName)
	}

	w.contID = contSummary.ID

	execResp, err := cli.ContainerExecCreate(ctx, contSummary.ID, dockercontainer.ExecOptions{
		Cmd:          []string{*w.vtyshPath},
		AttachStdin:  true,
		AttachStdout: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %v", err)
	}

	w.execID = execResp.ID

	attachResp, err := cli.ContainerExecAttach(ctx, w.execID, dockercontainer.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %v", err)
	}

	w.dockerIO = &attachResp

	err = cli.ContainerExecStart(ctx, w.execID, dockercontainer.ExecStartOptions{})
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

func (writer *ContainerVtyshConfigWriter) ExecuteCommands(ctx context.Context, commands []string) ([]byte, error) {
	trimmedCommands := make([]string, 0)
	for _, command := range commands {
		if c := strings.TrimSpace(command); c != "" {
			trimmedCommands = append(trimmedCommands, "-c")
			trimmedCommands = append(trimmedCommands, c)
		}
	}
	if len(trimmedCommands) == 0 {
		return nil, fmt.Errorf("no commands to execute")
	}
	cmd := make([]string, 0)
	cmd = append(cmd, *writer.vtyshPath)
	cmd = append(cmd, trimmedCommands...)

	cli, err := pkgutils.DockerCliFromCtx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get docker cli from context: %w", err)
	}

	execResp, err := cli.ContainerExecCreate(ctx, writer.contID, dockercontainer.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create exec: %v", err)
	}

	attachResp, err := cli.ContainerExecAttach(ctx, execResp.ID, dockercontainer.ExecAttachOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec: %v", err)
	}
	defer attachResp.Close()

	outputStrChan := make(chan []byte)
	errChan := make(chan error)
	go func() {
		var outBuf bytes.Buffer
		_, err := io.Copy(&outBuf, attachResp.Reader)
		if err != nil {
			errChan <- err
		}
		outputStrChan <- outBuf.Bytes()
	}()

	err = cli.ContainerExecStart(ctx, execResp.ID, dockercontainer.ExecStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to start exec: %v", err)
	}

	var outputStr []byte
	select {
	case err = <-errChan:
		return nil, fmt.Errorf("failed to copy output: %v", err)
	case outputStr = <-outputStrChan:
	}

	return outputStr, nil
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
