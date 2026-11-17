//go:build unix

package binwatch_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/binwatch"
)

func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700))
	return p
}

func TestTheProbeRunsTheBinaryAndReadsItsVersion(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	v, err := binwatch.OS{}.Probe(ctx, script(t, dir, "good", `[ "$1" = version ] && [ "$BASALT_UPDATE_CHECK" = off ] && echo "basalt 0.0.2"`))
	require.NoError(t, err)
	require.Equal(t, "0.0.2", v)

	_, err = binwatch.OS{}.Probe(ctx, script(t, dir, "other", `echo "something else"`))
	require.ErrorContains(t, err, "basalt version")
	_, err = binwatch.OS{}.Probe(ctx, script(t, dir, "fails", `exit 3`))
	require.Error(t, err)
	_, err = binwatch.OS{}.Probe(ctx, filepath.Join(dir, "missing"))
	require.Error(t, err)
}

func TestStatTellsAReplacedFileFromTheSameOne(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := script(t, dir, "basalt", "echo one")
	first, err := binwatch.OS{}.Stat(p)
	require.NoError(t, err)
	again, err := binwatch.OS{}.Stat(p)
	require.NoError(t, err)
	require.Equal(t, first, again)

	// An installer writes the new file beside it and renames it over.
	next := script(t, dir, "basalt.new", "echo two")
	require.NoError(t, os.Rename(next, p))
	replaced, err := binwatch.OS{}.Stat(p)
	require.NoError(t, err)
	require.NotEqual(t, first, replaced)
}
