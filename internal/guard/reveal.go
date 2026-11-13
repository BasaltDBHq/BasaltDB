package guard

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// RevealRefused is the one detail of APPROVAL_INVALID and REVERT_INVALID for
// every failed reveal proof, key, nonce or ticket check (CONTRACT.md, Rows
// hidden from the agent; version 29).
const RevealRefused = "REVEAL_REFUSED"

// RevealedRevert is reveal_revert_rows' answer: the values of the
// request's redacted lines, or RowsChanged (and no row) when a hidden row
// changed since the revert was prepared. Either way the proof used up the
// revert's reveal nonce.
type RevealedRevert struct {
	Rows        []approval.RevealedRow `json:"rows"`
	RowsChanged bool                   `json:"rowsChanged"`
}

// RevealNonce is the reveal nonce of the caller's own approval
// (approval.KindApprove) or revert (approval.KindRevert), which the person's
// reveal proof signs (basalt_meta.reveal_nonce, version 29). Another role's
// item, or none, is APPROVAL_INVALID "no such approval" or REVERT_INVALID
// "no such revert".
func RevealNonce(ctx context.Context, q Querier, kind string, id uuid.UUID) ([]byte, error) {
	var out []byte
	// Plain SQL: one function call returning bytea.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reveal_nonce($1::text, $2::uuid)`, kind, id.String()).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RevealRevertRows asks Postgres for the values of the caller's own
// pending revert's redacted lines with the person's reveal proof and the
// key the engine derived from the page's reveal secret
// (approval.RevealKey; never the secret). Every proof or key failure is
// REVERT_INVALID detail RevealRefused and changes nothing. Run it in its
// own transaction.
func RevealRevertRows(ctx context.Context, q Querier, revertID uuid.UUID, proof passkey.Assertion, key []byte) (RevealedRevert, error) {
	b, err := proofJSON(proof)
	if err != nil {
		return RevealedRevert{}, err
	}
	var out RevealedRevert
	// Plain SQL: one function call returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.reveal_revert_rows($1::uuid, $2::jsonb, $3::bytea)`,
		revertID.String(), b, key).Scan(&out)
	if err != nil {
		return RevealedRevert{}, err
	}
	return out, nil
}

// RevealRowsChanged is the detail of APPROVAL_INVALID when a re-run preview's
// lines no longer match the held approval's (reveal_approval_rows): the
// approval can no longer apply.
const RevealRowsChanged = "ROWS_CHANGED"

// OpenReveal checks the person's reveal proof for the caller's own pending
// approval (basalt_meta.open_reveal, version 30) with the key the engine
// derived from the page's reveal secret, and returns a ticket good for one
// re-run preview within 2 minutes. Every proof or key failure is
// APPROVAL_INVALID detail RevealRefused and changes nothing. Run it in its
// own transaction; keep the ticket in memory for this one request.
func OpenReveal(ctx context.Context, q Querier, approvalID uuid.UUID, proof passkey.Assertion, key []byte) ([]byte, error) {
	b, err := proofJSON(proof)
	if err != nil {
		return nil, err
	}
	var ticket []byte
	// Plain SQL: one function call returning bytea.
	err = q.QueryRow(ctx, `SELECT basalt_meta.open_reveal($1::uuid, $2::jsonb, $3::bytea)`,
		approvalID.String(), b, key).Scan(&ticket)
	if err != nil {
		return nil, err
	}
	return ticket, nil
}

// RevealApprovalRows returns the values of the held approval's redacted
// lines (basalt_meta.reveal_approval_rows, version 30). tx is a preview
// (BeginPreview) that re-ran the held statement with its parameters and
// recorded it with FinishChange, exactly as an apply does; roll it back
// afterwards. A missing, wrong or expired ticket, or a preview of another
// statement, parameters or run, is APPROVAL_INVALID detail RevealRefused;
// rows that changed since the hold are APPROVAL_INVALID detail
// RevealRowsChanged.
func RevealApprovalRows(ctx context.Context, tx pgx.Tx, approvalID uuid.UUID, ticket []byte) ([]approval.RevealedRow, error) {
	var out struct {
		Rows []approval.RevealedRow `json:"rows"`
	}
	// Plain SQL: one function call returning jsonb.
	err := tx.QueryRow(ctx, `SELECT basalt_meta.reveal_approval_rows($1::uuid, $2::bytea)`,
		approvalID.String(), ticket).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out.Rows, nil
}

// proofJSON is a passkey assertion as the guard's proof functions read it:
// base64url fields (rescope_revert, reveal_revert_rows, open_reveal).
func proofJSON(a passkey.Assertion) (string, error) {
	b, err := json.Marshal(rescopeProof{
		CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON: a.ClientDataJSON, Signature: a.Signature,
	})
	return string(b), err
}
