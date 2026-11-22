// Package chainpin keeps the last ledger chain head a reader verified, so
// the next check is incremental (basalt_meta.verify_chain_from) and a
// rewrite of history between two checks is caught. The engine keeps one
// file per agent in its state directory; basalt log keeps one per database
// and role in the user's cache directory. A pin lives outside the database
// on purpose: whoever can rewrite basalt_meta could rewrite a pin stored
// there too.
package chainpin

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// namePattern keeps pin names to one plain file name.
var namePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// ErrInvalidName is a pin name that is not a plain file name.
var ErrInvalidName = errors.New("invalid pin name")

// Pin is a verified chain head and the install of the guard it belongs to
// (the guard install id; uuid.Nil for a pin saved before install ids).
type Pin struct {
	Head    action.ChainHead
	Install uuid.UUID
	// SetAside are the pins this witness set aside after a reinstall and
	// reported in the ledger, kept so the notice stays whatever happens to
	// the ledger rows (CONTRACT.md, Version 36, step 4).
	SetAside []action.SetAside
}

// Kept returns p with s in its SetAside, once: the same pin set aside on
// the same install is kept once.
func (p Pin) Kept(s action.SetAside) Pin {
	for _, k := range p.SetAside {
		if k.PinnedSeq == s.PinnedSeq && k.PinnedInstall == s.PinnedInstall && k.Install == s.Install &&
			bytes.Equal(k.PinnedHash, s.PinnedHash) {
			return p
		}
	}
	p.SetAside = append(slices.Clone(p.SetAside), s)
	return p
}

// Of reports whether p belongs to install: a pin of another install is of a
// ledger that no longer exists, and is set aside, not checked. A pin with
// no install (saved before install ids, when a schema oid named the
// install and could repeat in another cluster) is taken as another
// install's, so it is moved or reported, never checked as this one's.
func (p Pin) Of(install uuid.UUID) bool { return p.Install != uuid.Nil && p.Install == install }

// CheckName refuses a pin name that is not one plain file name.
func CheckName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return nil
}

// Memory keeps pins in memory: the fallback when no state directory can be
// written, and tests.
type Memory struct {
	mu   sync.Mutex
	pins map[string]Pin
}

// Load returns the pin named name, and false when there is none yet.
func (m *Memory) Load(name string) (Pin, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.pins[name]
	return h, ok, nil
}

// Save replaces the pin named name.
func (m *Memory) Save(name string, p Pin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pins == nil {
		m.pins = map[string]Pin{}
	}
	m.pins[name] = p
	return nil
}
