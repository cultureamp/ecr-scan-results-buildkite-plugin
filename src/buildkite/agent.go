package buildkite

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	osexec "golang.org/x/sys/execabs"
)

type BuildkiteAgent struct {
}

func (a BuildkiteAgent) Annotate(ctx context.Context, message string, style string, annotationContext string) error {
	return execCmdWithStdin(ctx, "buildkite-agent", message, "annotate", "--style", style, "--context", annotationContext)
}

func (a BuildkiteAgent) ArtifactUpload(ctx context.Context, path string) error {
	return execAgentSyscall(ctx, "buildkite-agent", "artifact", "upload", path)
}

func execAgentSyscall(ctx context.Context, executableName string, args ...string) error {
	Logf("Executing: %s %s\n", executableName, strings.Join(args, " "))

	executable, err := osexec.LookPath(executableName)
	if err != nil {
		return err
	}

	execArgs := append([]string{executableName}, args...)
	return syscall.Exec(executable, execArgs, os.Environ())
}

func execCmdWithStdin(ctx context.Context, executableName string, stdin string, args ...string) error {
	Logf("Executing: %s %s\n", executableName, strings.Join(args, " "))

	cmd := osexec.CommandContext(ctx, executableName, args...)

	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan)

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		for {
			sig := <-sigChan
			_ = cmd.Process.Signal(sig)
		}
	}()

	if err := cmd.Wait(); err != nil {
		_ = cmd.Process.Signal(os.Kill)
		return fmt.Errorf("Failed to wait for command termination: %v", err)
	}

	waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)
	exitStatus := waitStatus.ExitStatus()
	if exitStatus != 0 {
		return fmt.Errorf("Command exited with non-zero status: %d", exitStatus)
	}

	return nil
}
