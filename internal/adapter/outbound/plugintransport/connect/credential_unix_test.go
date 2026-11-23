//go:build unix

package connect

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// statInfo is an os.FileInfo whose owner is set by the test.
type statInfo struct {
	os.FileInfo
	st *syscall.Stat_t
}

func (s statInfo) Sys() any { return s.st }

func TestCredentialFileOwnerMustBeTheEngine(t *testing.T) {
	path := writeToken(t, "zqx-owner-test-only", 0o600)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if rule := checkCredentialFileInfo(fi); rule != "" {
		t.Fatalf("the file this process wrote is its own: %s", rule)
	}
	st := *fi.Sys().(*syscall.Stat_t)
	st.Uid++
	if rule := checkCredentialFileInfo(statInfo{FileInfo: fi, st: &st}); !strings.Contains(rule, "not by the engine's user") {
		t.Fatalf("another user's file: rule %q", rule)
	}
}

func TestCredentialFileFIFODoesNotBlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo.token")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := readCredential(path); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("a FIFO: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
}
