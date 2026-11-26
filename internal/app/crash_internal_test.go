package app

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/crash"
)

func TestOnPanicSavesAScrubbedSharedReport(t *testing.T) {
	state := t.TempDir()
	env := agentEnv{stateDir: state}
	var stack []byte
	func() {
		defer func() { _ = recover(); stack = debug.Stack() }()
		panic("DELETE FROM customers WHERE email = 'a@b.example'")
	}()
	var logged bytes.Buffer
	errorID, id := env.onPanic(slog.New(slog.NewJSONHandler(&logged, nil)))("write", "DELETE FROM customers WHERE email = 'a@b.example'", stack)
	require.NotEmpty(t, id)
	require.NotEmpty(t, errorID)
	require.NotEqual(t, id, errorID)
	require.Contains(t, logged.String(), `"error_id":"`+errorID+`"`)
	require.Contains(t, logged.String(), `"report_id":"`+id+`"`)
	require.NotContains(t, logged.String(), "customers", "the log carries the ids, not the panic's value")

	dir := filepath.Join(state, servicespec.CrashDirName)
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

// With no report saved, the panic is still logged under the error id it
// answers with.
func TestOnPanicWithAnUnwritableStateDirReturnsNoReportID(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	var logged bytes.Buffer
	errorID, id := agentEnv{stateDir: file}.onPanic(slog.New(slog.NewJSONHandler(&logged, nil)))("write", "secret-value", nil)
	require.Empty(t, id)
	require.NotEmpty(t, errorID)
	require.Contains(t, logged.String(), `"error_id":"`+errorID+`"`)
	require.NotContains(t, logged.String(), "secret-value")
}
