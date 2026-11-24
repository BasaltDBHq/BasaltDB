package setup

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Machine is what the printed basalt mcp command reads of the computer.
type Machine interface {
	// Executable is the absolute, link-resolved path of the running binary.
	Executable() (string, error)
}

// MCPBinary is the program of the printed basalt mcp command: the absolute,
// link-resolved path of the running binary, which the agent app finds
// whatever its PATH is. Bare basalt only when the path is unknown.
func MCPBinary(h Machine) string {
	if exe, err := h.Executable(); err == nil {
		return exe
	}
	return "basalt"
}

// TemporaryBinaryWarning is a line to print after the mcp command when bin
// is in a folder that is often temporary (under tmp, or a Go build cache),
// else nothing. The command keeps the path; the person should move the
// binary somewhere that survives and register that path.
func TemporaryBinaryWarning(bin, tmp string) string {
	// bin is link-resolved; resolve tmp too, or a tmp that is a link
	// (macOS /var -> /private/var) never matches.
	if resolved, err := filepath.EvalSymlinks(tmp); err == nil {
		tmp = resolved
	}
	rel, err := filepath.Rel(tmp, bin)
	underTmp := err == nil && rel != "." && !strings.HasPrefix(rel, "..")
	if !underTmp && !strings.Contains(filepath.ToSlash(bin), "/go-build") {
		return ""
	}
	return fmt.Sprintf("basalt: %s is in a folder that may be cleared; put the binary in a folder that survives and register that path instead\n", bin)
}

// MCPArgs is basalt mcp for the agent, with bin as the program. basalt mcp
// finds the engine config and the socket directory by itself.
func MCPArgs(agent, bin string) []string {
	return []string{bin, "mcp", "--agent", agent}
}
