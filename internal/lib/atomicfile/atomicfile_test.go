package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestWriteReplacesWholeWithMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o644))
	require.NoError(t, Write(path, []byte("new"), Options{Mode: 0o600, SyncDir: true}))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "new", string(got))
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
	require.Equal(t, []string{"f"}, names(t, dir), "no temporary file left")
}

func TestFailedWriteKeepsOldFileAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))
	boom := errors.New("boom")
	err := WriteFunc(path, Options{Mode: 0o600}, func(f *os.File) error {
		_, _ = f.WriteString("half")
		return boom
	})
	require.ErrorIs(t, err, boom)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "old", string(got))
	require.Equal(t, []string{"f"}, names(t, dir))
}

func TestRefuseNonRegularRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	err := Write(link, []byte("x"), Options{Mode: 0o600, RefuseNonRegular: true})
	require.ErrorContains(t, err, "not a regular file")
	got, _ := os.ReadFile(target)
	require.Equal(t, "keep", string(got))

	// Without the option the link is replaced, never followed.
	require.NoError(t, Write(link, []byte("x"), Options{Mode: 0o600}))
	got, _ = os.ReadFile(target)
	require.Equal(t, "keep", string(got), "the link target is untouched")
	fi, err := os.Lstat(link)
	require.NoError(t, err)
	require.True(t, fi.Mode().IsRegular())
}

func TestConcurrentWritersLeaveOneWholeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte(fmt.Sprintf("writer-%02d-%s", i, string(make([]byte, 4096))))
			require.NoError(t, Write(path, body, Options{Mode: 0o600}))
		}()
	}
	wg.Wait()
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Len(t, got, len("writer-00-")+4096)
	require.Equal(t, []string{"f"}, names(t, dir))
}

func TestMissingDirectoryIsAnError(t *testing.T) {
	require.Error(t, Write(filepath.Join(t.TempDir(), "no", "f"), []byte("x"), Options{Mode: 0o600}))
}
