package ledger

import (
	"bytes"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// Head returns the head pinned on the last tick (tests).
func (u *Upkeep) Head() (action.ChainHead, bool) {
	if u.head == nil {
		return action.ChainHead{}, false
	}
	return action.ChainHead{Seq: u.head.Seq, Hash: bytes.Clone(u.head.Hash)}, true
}
