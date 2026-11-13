package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// The paths rescope_revert records in REVERT_RESCOPED (CONTRACT.md,
// basalt_meta, Version 21).
const (
	RescopeViaOwnWork    = "OWN_WORK"
	RescopeViaProof      = "PROOF"
	RescopeViaScopeToken = "SCOPE_TOKEN"
)

// RescopeRequest is one change of a pending revert's scope
// (basalt_meta.rescope_revert). Select is sent as is; Postgres normalizes
// it. A widen sets Proof and RescopeKey (revert.RescopeKey of the page's
// new link secret, never the secret); a narrow after a widen sets Token.
type RescopeRequest struct {
	RevertID   uuid.UUID
	Select     revert.Select
	Proof      *passkey.Assertion
	RescopeKey []byte
	Token      []byte
}

// CatalogAgent, CatalogRun and CatalogTable are what the person may pick
// from after a widen (revert-scope-response.schema.json, catalog).
type CatalogAgent struct {
	Agent   string `json:"agent"`
	Changes int    `json:"changes"`
}

type CatalogRun struct {
	RunID     uuid.UUID `json:"runId"`
	Agent     string    `json:"agent"`
	StartedAt time.Time `json:"startedAt"`
	Changes   int       `json:"changes"`
}

type CatalogTable struct {
	Table string `json:"table"`
	Rows  int    `json:"rows"`
}

// RevertCatalog lists the agents, runs and tables inside the select the
// person proved. Only a proven or token-bearing rescope returns it.
type RevertCatalog struct {
	Agents []CatalogAgent `json:"agents"`
	Runs   []CatalogRun   `json:"runs"`
	Tables []CatalogTable `json:"tables"`
}

// RescopedRevert is a revert after rescope_revert or reset_revert: the new
// binding and lines (a large plan's sample), the nonce the next widen proof
// signs, and for a proven or token-bearing call the catalog; ScopeToken is
// set only by a proven widen.
type RescopedRevert struct {
	RevertID     uuid.UUID      `json:"revertId"`
	BindingText  string         `json:"binding"`
	ExpiresAt    time.Time      `json:"expiresAt"`
	Lines        []string       `json:"lines"`
	RescopeNonce passkey.Bytes  `json:"rescopeNonce"`
	Catalog      *RevertCatalog `json:"catalog,omitempty"`
	ScopeToken   passkey.Bytes  `json:"scopeToken,omitempty"`
}

// rescopeProof is the proof as rescope_revert reads it: base64url fields.
type rescopeProof struct {
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

// RescopeRevert changes the scope of the caller's own pending revert
// (basalt_meta.rescope_revert). Inside the caller's own work it needs
// nothing while nobody widened the revert; anything wider, and anything
// after a widen, needs the person's proof or the scope token, and fails as
// REVERT_INVALID detail RevertWidenRefused otherwise. Run it in its own
// transaction.
func RescopeRevert(ctx context.Context, q Querier, req RescopeRequest) (RescopedRevert, error) {
	sel, err := json.Marshal(req.Select)
	if err != nil {
		return RescopedRevert{}, err
	}
	var proof any
	if req.Proof != nil {
		b, err := proofJSON(*req.Proof)
		if err != nil {
			return RescopedRevert{}, err
		}
		proof = b
	}
	var out RescopedRevert
	// Plain SQL: one function call returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.rescope_revert($1::uuid, $2::jsonb, $3::jsonb, $4::bytea, $5::bytea)`,
		req.RevertID.String(), string(sel), proof, req.RescopeKey, req.Token).Scan(&out)
	if err != nil {
		return RescopedRevert{}, err
	}
	return out, nil
}

// RescopeOwn changes the scope of the caller's own pending revert to s, the
// caller's own work (agents = [session_user]), with no proof or token
// (basalt_meta.rescope_revert): the person's CLI narrowing a revert, never
// widening it. A select outside the caller's own work, or any rescope of a
// widened revert, fails as REVERT_INVALID detail RevertWidenRefused. Run it
// in its own transaction.
func RescopeOwn(ctx context.Context, q Querier, revertID uuid.UUID, s RevertScope) (PreparedRevert, error) {
	args, err := s.args()
	if err != nil {
		return PreparedRevert{}, err
	}
	var out RescopedRevert
	// Plain SQL: one function call over a built descriptor, returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.rescope_revert($5::uuid, `+ownSelect+`, NULL, NULL, NULL)`,
		append(args, revertID.String())...).Scan(&out)
	if err != nil {
		return PreparedRevert{}, err
	}
	b, err := revert.ParseBinding(out.BindingText)
	if err != nil {
		return PreparedRevert{}, fmt.Errorf("guard returned a bad revert binding: %w", err)
	}
	return PreparedRevert{
		RevertID: out.RevertID, BindingText: out.BindingText, ExpiresAt: out.ExpiresAt, Lines: out.Lines,
		Batched: b.Batched,
	}, nil
}

// ResetRevert puts the caller's own pending revert back to its proposal
// (basalt_meta.reset_revert), for the agent's reissueLink on a widened
// revert: the person's scope, ceiling and token are dropped and the reset
// is recorded (REVERT_RESET).
func ResetRevert(ctx context.Context, q Querier, revertID uuid.UUID) (RescopedRevert, error) {
	var out RescopedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reset_revert($1::uuid)`, revertID.String()).Scan(&out)
	if err != nil {
		return RescopedRevert{}, err
	}
	return out, nil
}

// RevertNonce is the rescope nonce of the caller's own revert, which the
// person's next widen proof signs (basalt_meta.revert_nonce, version 22).
// Another role's revert, or none, is REVERT_INVALID "no such revert".
func RevertNonce(ctx context.Context, q Querier, revertID uuid.UUID) ([]byte, error) {
	var out []byte
	// Plain SQL: one function call returning bytea.
	err := q.QueryRow(ctx, `SELECT basalt_meta.revert_nonce($1::uuid)`, revertID.String()).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// The paths reject_revert records in REVERT_REJECTED (CONTRACT.md,
// basalt_meta, Version 23): no token, so Postgres cannot tell the person on
// the link from the agent holding it; or the scope token of a widened
// revert, which only the engine holds for the person's rotated link.
const (
	RejectViaLinkOrAgent = "LINK_OR_AGENT"
	RejectViaScopeToken  = "SCOPE_TOKEN"
)

// MaxRejectNote is the longest note the person may leave with a reject, in
// characters (reverts.reject_note).
const MaxRejectNote = 500

// RejectedRevert is reject_revert's answer.
type RejectedRevert struct {
	RevertID   uuid.UUID `json:"revertId"`
	Status     string    `json:"status"`
	RejectedAt time.Time `json:"rejectedAt"`
}

// RejectRevert marks the caller's own pending, unsigned revert REJECTED
// (basalt_meta.reject_revert, version 23) with the person's note ("" for
// none). Once the person widened the revert, token must be its scope token;
// before that it is nil. A missing or wrong token is REVERT_INVALID detail
// RevertWidenRefused; another role's revert, or none, is REVERT_INVALID "no
// such revert".
func RejectRevert(ctx context.Context, q Querier, revertID uuid.UUID, note string, token []byte) (RejectedRevert, error) {
	var out RejectedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reject_revert($1::uuid, $2::text, $3::bytea)`,
		revertID.String(), note, token).Scan(&out)
	if err != nil {
		return RejectedRevert{}, err
	}
	return out, nil
}
