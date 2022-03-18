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
	executable, err := osexec.LookPath("buildkite-agent")
	if err != nil {
		return err
	}

	// run command buildkite-agent annotate --style <style> --context <context> <message>
	return syscall.Exec(executable, []string{"annotate", "--style", style, "--context", annotationContext, message}, os.Environ())
}
