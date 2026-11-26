//go:build unix

package connect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

func TestCredentialFileRefusesASecondHardLink(t *testing.T) {
	path := writeToken(t, "zqx-link-test-only", 0o600)
	if err := os.Link(path, filepath.Join(t.TempDir(), "elsewhere")); err != nil {
		t.Fatal(err)
	}
	_, err := readCredential(path)
	if !errors.Is(err, ErrCredentialFile) || !strings.Contains(err.Error(), "more than one hard link") {
		t.Fatalf("a second hard link: %v", err)
	}
	if strings.Contains(err.Error(), "zqx") {
		t.Fatalf("the error carries the contents: %v", err)
	}
}

func TestCredentialFileRuleTexts(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&ownerfile.RefusedError{Rule: ownerfile.Symlink}, "must be a regular file, not a link or directory"},
		{&ownerfile.RefusedError{Rule: ownerfile.Owner, UID: 7, Want: "by the engine's user (uid 501)"}, "is owned by uid 7, not by the engine's user (uid 501)"},
		{&ownerfile.RefusedError{Rule: ownerfile.Mode, Perm: 0o640}, "is mode 640; it must be readable by the engine's user only (0600)"},
		{&ownerfile.RefusedError{Rule: ownerfile.TooLarge}, "is larger than 16 KiB"},
		{fs.ErrNotExist, "does not exist"},
		{errors.New("EIO"), "cannot be read"},
	} {
		if got := credentialRule(tc.err); got != tc.want {
			t.Fatalf("%v: rule %q, want %q", tc.err, got, tc.want)
		}
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
