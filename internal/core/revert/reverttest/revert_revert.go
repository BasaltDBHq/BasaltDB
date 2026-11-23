package reverttest

import (
	"slices"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
)

// Sample returns the lines a revert link carries for a plan whose lines are
// in signed order: the SKIP lines, then the RESTORE lines, each group in
// signed order and cut to SampleCounts (decisions N12-4, RSS-1). Postgres
// builds the same sample in prepare_revert.
func Sample(lines []string) ([]string, error) {
	skips := make([]string, 0, len(lines))
	restores := make([]string, 0, len(lines))
	for _, text := range lines {
		l, err := revert.ParseLine(text)
		if err != nil {
			return nil, err
		}
		if l.Action == revert.ActionSkip {
			skips = append(skips, text)
			continue
		}
		restores = append(restores, text)
	}
	s, r := revert.SampleCounts(len(skips), len(restores))
	return slices.Concat(skips[:s], restores[:r]), nil
}

// fromCompact is the request a format 2 link carries, its id read from the
// binding; Check refuses a binding that does not parse.
func fromCompact(binding string, lines []string, ids []passkey.Bytes) revert.Request {
	r := revert.Request{Binding: binding, Lines: lines, CredentialIDs: ids}
	if b, err := revert.ParseBinding(binding); err == nil {
		r.RevertID = b.RevertID
	}
	return r
}

// ParseRequest decodes a revert link fragment of either format, with or
// without '#', and checks it (Check).
func ParseRequest(fragment string) (revert.Request, revert.Binding, error) {
	r, err := linkcodec.DecodeRequest(fragment, revert.MaxLines, fromCompact)
	if err != nil {
		return revert.Request{}, revert.Binding{}, revert.Invalid("revert request %v", err)
	}
	if r.RescopeNonce != nil || r.RevealNonce != nil || r.Columns != nil {
		return revert.Request{}, revert.Binding{}, revert.Invalid("a link carries no rescopeNonce, revealNonce or columns: only the engine serves them")
	}
	b, err := r.Check()
	if err != nil {
		return revert.Request{}, revert.Binding{}, err
	}
	return r, b, nil
}

// NewResponse wraps an assertion for revertID.
func NewResponse(revertID uuid.UUID, a passkey.Assertion) revert.Response {
	return revert.Response{
		RevertID:          revertID,
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	}
}
