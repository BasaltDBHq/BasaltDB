package connect

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrCredentialFile: the entry's auth.credentialFile was refused. The error
// names the file and the rule it broke, never what the file holds.
var ErrCredentialFile = errors.New("the credential file is refused")

// maxCredentialBytes caps the credential file: a bearer token is short, and
// the engine never reads an unbounded file into a header.
const maxCredentialBytes = 16 << 10

// credentialError names the file and the rule, never its contents.
func credentialError(path, rule string) error {
	return fmt.Errorf("connect: credential file %s %s: %w", path, rule, ErrCredentialFile)
}

// readCredential reads the bearer token from path. Dial reads it once, when
// the engine connects to the entry; a changed token takes effect when the
// entry is started again. It must be an absolute path to a regular file (a
// symlink is refused), owned by the engine's user and readable by that user
// only (mode 0600 or narrower), at most 16 KiB. One trailing newline (LF or
// CRLF) is dropped; what is left must be non-empty visible ASCII, so it can
// never split or add a header line.
func readCredential(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", credentialError(path, "must be an absolute path")
	}
	link, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", credentialError(path, "does not exist")
	}
	if err != nil {
		return "", credentialError(path, "cannot be read")
	}
	if !link.Mode().IsRegular() {
		return "", credentialError(path, "must be a regular file, not a link or directory")
	}
	f, err := openNoFollow(path)
	if err != nil {
		return "", credentialError(path, "cannot be read")
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", credentialError(path, "cannot be read")
	}
	if !os.SameFile(link, fi) || !fi.Mode().IsRegular() {
		return "", credentialError(path, "must be a regular file, not a link or directory")
	}
	if rule := checkCredentialFileInfo(fi); rule != "" {
		return "", credentialError(path, rule)
	}
	if fi.Size() > maxCredentialBytes {
		return "", credentialError(path, "is larger than 16 KiB")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	defer clear(raw)
	if err != nil {
		return "", credentialError(path, "cannot be read")
	}
	if len(raw) > maxCredentialBytes {
		return "", credentialError(path, "is larger than 16 KiB")
	}
	return parseToken(path, raw)
}

// parseToken drops one trailing newline and checks what is left.
func parseToken(path string, raw []byte) (string, error) {
	tok := raw
	if n := len(tok); n > 0 && tok[n-1] == '\n' {
		tok = tok[:n-1]
		if n := len(tok); n > 0 && tok[n-1] == '\r' {
			tok = tok[:n-1]
		}
	}
	if len(tok) == 0 {
		return "", credentialError(path, "is empty")
	}
	for _, b := range tok {
		if b < '!' || b > '~' {
			return "", credentialError(path, "must hold one token of visible ASCII characters, with no space or line break inside")
		}
	}
	return string(tok), nil
}
