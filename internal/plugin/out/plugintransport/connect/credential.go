package connect

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
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
// entry is started again. It must be an absolute path to a regular file with
// one link (a symlink is refused), owned by the engine's user and readable
// by that user only (mode 0600 or narrower), at most 16 KiB: ownerfile's
// rules, checked on the descriptor it reads. One trailing newline (LF or
// CRLF) is dropped; what is left must be non-empty visible ASCII, so it can
// never split or add a header line.
func readCredential(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", credentialError(path, "must be an absolute path")
	}
	rules := ownerfile.Rules{MaxBytes: maxCredentialBytes, OwnerName: fmt.Sprintf("by the engine's user (uid %d)", os.Geteuid())}
	raw, _, err := ownerfile.Read(path, rules)
	defer clear(raw)
	if err != nil {
		return "", credentialError(path, credentialRule(err))
	}
	return parseToken(path, raw)
}

// credentialRule is the rule a refused read broke, in the error's words.
func credentialRule(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "does not exist"
	}
	re := ownerfile.Refusal(err)
	if re == nil {
		return "cannot be read"
	}
	switch re.Rule {
	case ownerfile.Symlink, ownerfile.NotRegular:
		return "must be a regular file, not a link or directory"
	case ownerfile.HardLinks:
		return "has more than one hard link; it must be a file of its own"
	case ownerfile.Owner:
		return "is " + re.Error()
	case ownerfile.Mode:
		return fmt.Sprintf("is mode %o; it must be readable by the engine's user only (0600)", re.Perm)
	case ownerfile.TooLarge:
		return "is larger than 16 KiB"
	case ownerfile.Changed, ownerfile.Unlinked:
	}
	return "cannot be read"
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
