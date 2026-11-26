package guard

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revertstore"
)

// rescopeProof is the proof as rescope_revert reads it: base64url fields.
type rescopeProof struct {
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

// selectJSON is a revert scope descriptor as rescope_revert reads it
// (CONTRACT.md, Revert, revert-select.schema.json): agents agent:<name>
// and resources.
type selectJSON struct {
	Scope     revert.Scope `json:"scope"`
	ScopeID   uuid.UUID    `json:"scopeId"`
	Agents    []string     `json:"agents"`
	Runs      []uuid.UUID  `json:"runs"`
	Resources []string     `json:"resources"`
}

// rescopedJSON is rescope_revert's and reset_revert's answer as the guard
// writes it: its catalog lists resources (revert-scope-response.schema.json).
type rescopedJSON struct {
	revertstore.RescopedRevert
	Catalog *struct {
		Agents    []revertstore.CatalogAgent `json:"agents"`
		Runs      []revertstore.CatalogRun   `json:"runs"`
		Resources []struct {
			Resource string `json:"resource"`
			Rows     int    `json:"rows"`
		} `json:"resources"`
		ChangeAgents map[uuid.UUID]string `json:"changeAgents,omitempty"`
	} `json:"catalog,omitempty"`
}

// decodeRescoped reads rescope_revert's or reset_revert's jsonb answer.
func decodeRescoped(raw []byte) (revertstore.RescopedRevert, error) {
	var in rescopedJSON
	if err := json.Unmarshal(raw, &in); err != nil {
		return revertstore.RescopedRevert{}, fmt.Errorf("decode rescope answer: %w", err)
	}
	out := in.RescopedRevert
	out.Catalog = nil
	if c := in.Catalog; c != nil {
		out.Catalog = &revertstore.RevertCatalog{
			Agents: c.Agents, Runs: c.Runs, ChangeAgents: c.ChangeAgents,
			Tables: make([]revertstore.CatalogTable, 0, len(c.Resources)),
		}
		for _, r := range c.Resources {
			out.Catalog.Tables = append(out.Catalog.Tables, revertstore.CatalogTable{Table: r.Resource, Rows: r.Rows})
		}
	}
	return out, nil
}

// RescopeRevert changes the scope of the caller's own pending revert
// (basalt_meta.rescope_revert). Inside the caller's own work it needs
// nothing while nobody widened the revert; anything wider, and anything
// after a widen, needs the person's proof or the scope token, and fails as
// REVERT_INVALID detail RevertWidenRefused otherwise. Run it in its own
// transaction.
func RescopeRevert(ctx context.Context, q Querier, req revertstore.RescopeRequest) (revertstore.RescopedRevert, error) {
	sel, err := json.Marshal(selectJSON{
		Scope: req.Select.Scope, ScopeID: req.Select.ScopeID, Agents: req.Select.Agents,
		Runs: req.Select.Runs, Resources: req.Select.Resources,
	})
	if err != nil {
		return revertstore.RescopedRevert{}, err
	}
	var proof any
	if req.Proof != nil {
		b, err := proofJSON(*req.Proof)
		if err != nil {
			return revertstore.RescopedRevert{}, err
		}
		proof = b
	}
	var raw []byte
	// Plain SQL: one function call returning jsonb.
	err = q.QueryRow(ctx, `SELECT basalt_meta.rescope_revert($1::uuid, $2::jsonb, $3::jsonb, $4::bytea, $5::bytea)`,
		req.RevertID.String(), string(sel), proof, req.RescopeKey, req.Token).Scan(&raw)
	if err != nil {
		return revertstore.RescopedRevert{}, err
	}
	return decodeRescoped(raw)
}

// ResetRevert puts the caller's own pending revert back to its proposal
// (basalt_meta.reset_revert), for the agent's reissueLink on a widened
// revert: the person's scope, ceiling and token are dropped and the reset
// is recorded (REVERT_RESET).
func ResetRevert(ctx context.Context, q Querier, revertID uuid.UUID) (revertstore.RescopedRevert, error) {
	var raw []byte
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reset_revert($1::uuid)`, revertID.String()).Scan(&raw)
	if err != nil {
		return revertstore.RescopedRevert{}, err
	}
	return decodeRescoped(raw)
}

// RevertNonce is the rescope nonce of the caller's own revert, which the
// person's next widen proof signs (basalt_meta.revert_nonce, version 22).
// Another role's revert, or none, is REVERT_INVALID NO_SUCH_REVERT
// (RevertNotFound).
func RevertNonce(ctx context.Context, q Querier, revertID uuid.UUID) ([]byte, error) {
	var out []byte
	// Plain SQL: one function call returning bytea.
	err := q.QueryRow(ctx, `SELECT basalt_meta.revert_nonce($1::uuid)`, revertID.String()).Scan(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RejectRevert marks the caller's own pending, unsigned revert REJECTED
// (basalt_meta.reject_revert, version 23) with the person's note ("" for
// none). Once the person widened the revert, token must be its scope token;
// before that it is nil. A missing or wrong token is REVERT_INVALID detail
// RevertWidenRefused; another role's revert, or none, is REVERT_INVALID "no
// such revert".
func RejectRevert(ctx context.Context, q Querier, revertID uuid.UUID, note string, token []byte) (revertstore.RejectedRevert, error) {
	var out revertstore.RejectedRevert
	// Plain SQL: one function call returning jsonb.
	err := q.QueryRow(ctx, `SELECT basalt_meta.reject_revert($1::uuid, $2::text, $3::bytea)`,
		revertID.String(), note, token).Scan(&out)
	if err != nil {
		return revertstore.RejectedRevert{}, err
	}
	return out, nil
}
