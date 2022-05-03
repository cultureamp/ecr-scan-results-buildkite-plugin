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

type Agent struct {
}

func (a Agent) Annotate(ctx context.Context, message string, style string, annotationContext string) error {
	return execCmd(ctx, "buildkite-agent", &message, "annotate", "--style", style, "--context", annotationContext)
}

func (a Agent) ArtifactUpload(ctx context.Context, path string) error {
	return execCmd(ctx, "buildkite-agent", nil, "artifact", "upload", path)
}

func execCmd(ctx context.Context, executableName string, stdin *string, args ...string) error {
	Logf("Executing: %s %s\n", executableName, strings.Join(args, " "))

	cmd := osexec.CommandContext(ctx, executableName, args...)

	if stdin != nil {
		cmd.Stdin = strings.NewReader(*stdin)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Relay incoming signals to the executing command.
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
		return fmt.Errorf("failed to wait for command termination: %w", err)
	}

	waitStatus := cmd.ProcessState.Sys().(syscall.WaitStatus)
	exitStatus := waitStatus.ExitStatus()
	if exitStatus != 0 {
		return fmt.Errorf("command exited with non-zero status: %d", exitStatus)
	}

	return nil
}
