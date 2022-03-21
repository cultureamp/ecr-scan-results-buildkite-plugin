package buildkite

import (
	"context"
	"os"
	"syscall"

	osexec "golang.org/x/sys/execabs"
)

type BuildkiteAgent struct {
}

func (a BuildkiteAgent) Annotate(ctx context.Context, message string, style string, annotationContext string) error {
	return execAgentCommand(ctx, "annotate", "--style", style, "--context", annotationContext, message)
}

func (a BuildkiteAgent) ArtifactUpload(ctx context.Context, path string) error {
	return execAgentCommand(ctx, "artifact", "upload", path)
}

func execAgentCommand(ctx context.Context, command string, args ...string) error {
	executableName := "buildkite-agent"
	executable, err := osexec.LookPath(executableName)
	if err != nil {
		return err
	}

	execArgs := append([]string{executableName}, args...)
	return syscall.Exec(executable, execArgs, os.Environ())
}
