package guardmodel

import (
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
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
// person proved, and from basalt_meta version 32 the agent role of each
// change in it (owner decision Q-11), so the page can tag every row. Only a
// proven or token-bearing rescope returns it; ChangeAgents is nil on an
// older guard.
type RevertCatalog struct {
	Agents       []CatalogAgent       `json:"agents"`
	Runs         []CatalogRun         `json:"runs"`
	Tables       []CatalogTable       `json:"tables"`
	ChangeAgents map[uuid.UUID]string `json:"changeAgents,omitempty"`
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
