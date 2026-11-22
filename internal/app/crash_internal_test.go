package engine

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/crash"
)

func TestOnPanicSavesAScrubbedSharedReport(t *testing.T) {
	state := t.TempDir()
	env := agentEnv{stateDir: state}
	var stack []byte
	func() {
		defer func() { _ = recover(); stack = debug.Stack() }()
		panic("DELETE FROM customers WHERE email = 'a@b.example'")
	}()
	id := env.onPanic("write", "DELETE FROM customers WHERE email = 'a@b.example'", stack)
	require.NotEmpty(t, id)

	dir := filepath.Join(state, crash.DirName)
	reports := crash.List(dir)
	require.Len(t, reports, 1)
	require.Equal(t, id, reports[0].ID)
	require.Equal(t, "write", reports[0].Command)
	require.Equal(t, "INTERNAL", reports[0].ErrorCode)
	require.NotContains(t, reports[0].Show(), "customers")

	info, err := os.Stat(filepath.Join(dir, id+".json"))
	require.NoError(t, err)
	require.NotZero(t, info.Mode().Perm()&0o004, "the person can read what the engine saved")
}

func TestOnPanicWithAnUnwritableStateDirReturnsNoID(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	require.Empty(t, agentEnv{stateDir: file}.onPanic("write", "x", nil))
}
