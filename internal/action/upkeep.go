package action

import (
	"time"

	"github.com/google/uuid"
)

// ChainHead is the last appended ledger entry: its sequence number and
// hash.
type ChainHead struct {
	Seq  int64
	Hash []byte
}

// ChainStatus is the result of a check of the ledger chain.
type ChainStatus struct {
	Intact bool
	// BrokenAt is the first seq that does not verify (or is missing).
	BrokenAt int64
}

// SetAside is a pinned chain head set aside after the ledger was installed
// again: the pin, the install it was verified on, the install it was set
// aside on, and when.
type SetAside struct {
	PinnedSeq  int64
	PinnedHash []byte
	// PinnedInstall is the install the pin was verified on, Install the one
	// it was set aside on.
	PinnedInstall uuid.UUID
	Install       uuid.UUID
	At            time.Time
}

// PinFate is what became of a pin of another install.
type PinFate int

const (
	// PinKept: the pin could not be reported; it is checked as before, so
	// the reinstall shows as a broken chain.
	PinKept PinFate = iota
	// PinMoved: the pinned entry is still on the current chain, which
	// verifies: the same ledger under a new install. The pin moves to it.
	PinMoved
	// PinSetAside: the pin was reported in the ledger and is set aside;
	// the new chain is checked from its start.
	PinSetAside
)

// SettledPin is what became of a pin of another install.
type SettledPin struct {
	Fate PinFate
	// Head is the head verified from the pin when it moved, to pin next.
	Head ChainHead
	// RecordErr is why the pin could not be reported (PinKept).
	RecordErr error
}

// Uncovered is an agent-writable target the ledger does not guard.
type Uncovered struct {
	Table string
	Why   string
}

// PruneResult is what one retention pass removed.
type PruneResult struct {
	ValuesPruned int64
	RowsDeleted  int64
}
