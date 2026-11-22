// Package browser opens a URL in the person's default browser: `open` on
// macOS, `xdg-open` on Linux. Both the CLI and `basalt mcp` use it.
package browser

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// Command is the command that opens a URL in the default browser on goos;
// false where there is none.
func Command(goos string) (string, bool) {
	switch goos {
	case "darwin":
		return "open", true
	case "linux":
		return "xdg-open", true
	}
	return "", false
}

// Open opens link in the default browser of this machine. The link is one
// argument, never passed through a shell.
func Open(ctx context.Context, link string) error {
	name, ok := Command(runtime.GOOS)
	if !ok {
		return fmt.Errorf("no browser opener on %s", runtime.GOOS)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s not found", name)
	}
	return exec.CommandContext(ctx, path, link).Run()
}
