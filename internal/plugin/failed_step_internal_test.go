package plugin

import (
	"fmt"
	"io/fs"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

func TestFailedStepTakesOnlyTheAdaptersStepError(t *testing.T) {
	t.Parallel()
	for _, op := range []string{opOpen, opStat, opRead, opCreate, opWrite} {
		require.Equal(t, op, failedStep(&fs.PathError{Op: op, Path: "p", Err: syscall.ENOENT}), op)
	}
	osErr := &fs.PathError{Op: opOpen, Path: "p", Err: syscall.ENOENT}
	for name, err := range map[string]error{
		"nil":                         nil,
		"a check's refusal":           pluginmodel.PathRefusal("p", "is not a regular file"),
		"a check that wraps os error": fmt.Errorf("check: %w", osErr),
		"an os error of another op":   &fs.PathError{Op: "chmod", Path: "p", Err: syscall.EPERM},
		"an os.Root open":             &fs.PathError{Op: "openat", Path: "p", Err: syscall.ENOENT},
	} {
		require.Empty(t, failedStep(err), name)
	}
}
