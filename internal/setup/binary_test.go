package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type machine struct{ exe string }

func (m machine) Executable() (string, error) { return m.exe, nil }

// basalt mcp finds the config and the socket directory itself, so the line
// is the same wherever the config is.
func TestMCPArgsNameOnlyTheAgent(t *testing.T) {
	t.Parallel()
	const bin = "/opt/basalt/bin/basalt"
	require.Equal(t, []string{"basalt", "mcp", "--agent", "bot"}, MCPArgs("bot", "basalt"))
	require.Equal(t, []string{bin, "mcp", "--agent", "bot"}, MCPArgs("bot", MCPBinary(machine{bin})))
}

func TestTemporaryBinaryWarning(t *testing.T) {
	t.Parallel()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.Contains(t, TemporaryBinaryWarning(filepath.Join(tmp, "x", "basalt"), tmp), "put the binary in a folder that survives")
	require.Contains(t, TemporaryBinaryWarning("/home/u/.cache/go-build/ab/basalt", tmp), "/home/u/.cache/go-build/ab/basalt")
	require.Empty(t, TemporaryBinaryWarning("/opt/basalt/bin/basalt", tmp))
	require.Empty(t, TemporaryBinaryWarning(tmp+"x/basalt", tmp))
}

func TestTemporaryBinaryWarningResolvesLinkedTempDir(t *testing.T) {
	t.Parallel()
	realTmp, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	link := filepath.Join(t.TempDir(), "tmp-link")
	require.NoError(t, os.Symlink(realTmp, link))
	bin := filepath.Join(realTmp, "basalt")
	require.Contains(t, TemporaryBinaryWarning(bin, link), "put the binary in a folder that survives")
	require.Empty(t, TemporaryBinaryWarning("/opt/basalt/bin/basalt", link))
}
