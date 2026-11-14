package person

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// The wire shapes of CONTRACT.md, The person socket. Each DTO maps from and
// to its domain type; byte strings are base64url (passkey.Bytes).

// PagesDTO is PAGES's result.
type PagesDTO struct {
	PagesURL    string `json:"pagesUrl"`
	LocalOrigin string `json:"localOrigin"`
}

type emptyParams struct{}

// accessDTO is LIST_ACCESS's result; the lists are never null.
type accessDTO struct {
	Read       []string `json:"read"`
	Write      []string `json:"write"`
	NotGranted []string `json:"notGranted"`
}

func accessFromDomain(a pgcatalog.Access) accessDTO {
	return accessDTO{Read: nonNil(a.Read), Write: nonNil(a.Write), NotGranted: nonNil(a.NotGranted)}
}

func (d accessDTO) toDomain() pgcatalog.Access {
	return pgcatalog.Access{Read: d.Read, Write: d.Write, NotGranted: d.NotGranted}
}

type headDTO struct {
	Seq  int64         `json:"seq"`
	Hash passkey.Bytes `json:"hash"`
}

func headFromDomain(h guard.ChainHead) headDTO { return headDTO{Seq: h.Seq, Hash: h.Hash} }
func (h headDTO) toDomain() guard.ChainHead    { return guard.ChainHead{Seq: h.Seq, Hash: h.Hash} }

// pinDTO is CHECK_HEALTH's pin: a head and the guard install it was
// verified on, absent when unknown.
type pinDTO struct {
	Seq     int64         `json:"seq"`
	Hash    passkey.Bytes `json:"hash"`
	Install uint32        `json:"install,omitempty"`
}

// setAsideDTO is one pin the reader set aside and kept (chainpin's
// setAside), sent so the engine's notice shows the reader's kept copy too.
type setAsideDTO struct {
	PinnedSeq     int64         `json:"pinnedSeq"`
	PinnedHash    passkey.Bytes `json:"pinnedHash"`
	PinnedInstall uint32        `json:"pinnedInstall"`
	Install       uint32        `json:"install"`
	At            time.Time     `json:"at"`
}

type healthParams struct {
	Full     bool          `json:"full"`
	Pin      *pinDTO       `json:"pin"`
	SetAside []setAsideDTO `json:"setAside,omitempty"`
}

func healthParamsFromDomain(o ledger.HealthOptions) healthParams {
	p := healthParams{Full: o.Full}
	if o.Pin != nil {
		p.Pin = &pinDTO{Seq: o.Pin.Seq, Hash: o.Pin.Hash, Install: o.PinInstall}
	}
	for _, s := range o.SetAside {
		p.SetAside = append(p.SetAside, setAsideDTO{
			PinnedSeq: s.PinnedSeq, PinnedHash: s.PinnedHash, PinnedInstall: s.PinnedInstall, Install: s.Install, At: s.At,
		})
	}
	return p
}

func (p healthParams) toDomain() ledger.HealthOptions {
	o := ledger.HealthOptions{Full: p.Full}
	if p.Pin != nil {
		o.Pin, o.PinInstall = &guard.ChainHead{Seq: p.Pin.Seq, Hash: p.Pin.Hash}, p.Pin.Install
	}
	for _, s := range p.SetAside {
		o.SetAside = append(o.SetAside, guard.SetAside{
			PinnedSeq: s.PinnedSeq, PinnedHash: s.PinnedHash, PinnedInstall: s.PinnedInstall, Install: s.Install, At: s.At,
		})
	}
	return o
}

// reinstallDTO is one entry of CHECK_HEALTH's reinstalls: the notice's
// data. more and moreAgents carry the counts the notice prints.
type reinstallDTO struct {
	Install     uint32               `json:"install"`
	InstalledAt *time.Time           `json:"installedAt"`
	InstalledBy string               `json:"installedBy,omitempty"`
	VaultUser   string               `json:"vaultUser,omitempty"`
	Reports     []reinstallReportDTO `json:"reports"`
	MoreAgents  int                  `json:"moreAgents,omitempty"`
}

type reinstallReportDTO struct {
	Agent      string        `json:"agent"`
	At         time.Time     `json:"at"`
	PinnedSeq  int64         `json:"pinnedSeq"`
	PinnedHash passkey.Bytes `json:"pinnedHash"`
	More       int           `json:"more,omitempty"`
}

func reinstallsFromDomain(rs guard.Reinstalls) []reinstallDTO {
	out := make([]reinstallDTO, 0, len(rs.List))
	for _, r := range rs.List {
		d := reinstallDTO{
			Install: r.Install, InstalledAt: r.InstalledAt, InstalledBy: r.InstalledBy, VaultUser: r.VaultUser,
			Reports: make([]reinstallReportDTO, 0, len(r.Reports)), MoreAgents: r.MoreAgents,
		}
		for _, rep := range r.Reports {
			d.Reports = append(d.Reports, reinstallReportDTO{
				Agent: rep.Agent, At: rep.At, PinnedSeq: rep.PinnedSeq, PinnedHash: rep.PinnedHash, More: rep.More,
			})
		}
		out = append(out, d)
	}
	return out
}

func reinstallsToDomain(list []reinstallDTO, earlier int) guard.Reinstalls {
	out := guard.Reinstalls{Earlier: earlier}
	for _, d := range list {
		r := guard.Reinstall{
			Install: d.Install, InstalledAt: d.InstalledAt, InstalledBy: d.InstalledBy, VaultUser: d.VaultUser, MoreAgents: d.MoreAgents,
		}
		for _, rep := range d.Reports {
			r.Reports = append(r.Reports, guard.ReinstallReport{
				Agent: rep.Agent, At: rep.At, PinnedSeq: rep.PinnedSeq, PinnedHash: rep.PinnedHash, More: rep.More,
			})
		}
		out.List = append(out.List, r)
	}
	return out
}

type chainDTO struct {
	Intact   bool  `json:"intact"`
	BrokenAt int64 `json:"brokenAt"`
}

type uncoveredDTO struct {
	Table string `json:"table"`
	Why   string `json:"why"`
}

type deadManDTO struct {
	At            time.Time `json:"at"`
	LastHeartbeat string    `json:"lastHeartbeat"`
	SilentHours   int64     `json:"silentHours"`
}

type healthDTO struct {
	Chain       chainDTO       `json:"chain"`
	Head        headDTO        `json:"head"`
	Install     uint32         `json:"install"`
	PinSetAside bool           `json:"pinSetAside"`
	PinMoved    bool           `json:"pinMoved"`
	Reinstalls  []reinstallDTO `json:"reinstalls"`
	// EarlierReinstalls counts the reinstalls past those in Reinstalls.
	EarlierReinstalls int            `json:"earlierReinstalls"`
	Uncovered         []uncoveredDTO `json:"uncovered"`
	RLSBlind          []string       `json:"rlsBlind"`
	LastHeartbeat     time.Time      `json:"lastHeartbeat"`
	HeartbeatStale    bool           `json:"heartbeatStale"`
	DeadMan           *deadManDTO    `json:"deadMan"`
	// PII is absent before guard version 15.
	PII *piiHealthDTO `json:"pii,omitempty"`
}

type piiHealthDTO struct {
	Classified        int                  `json:"classified"`
	Unclassified      int                  `json:"unclassified"`
	UnclassifiedNames []string             `json:"unclassifiedNames"`
	Review            int                  `json:"review"`
	ReviewNames       []string             `json:"reviewNames"`
	Dictionary        *dictionaryHealthDTO `json:"dictionary,omitempty"`
}

type dictionaryHealthDTO struct {
	Values     uint64     `json:"values"`
	LastScanAt *time.Time `json:"lastScanAt,omitempty"`
}

func piiHealthFromDomain(p *ledger.PIIHealth) *piiHealthDTO {
	if p == nil {
		return nil
	}
	out := &piiHealthDTO{
		Classified: p.Classified, Unclassified: p.Unclassified, UnclassifiedNames: nonNil(p.UnclassifiedNames),
		Review: p.Review, ReviewNames: nonNil(p.ReviewNames),
	}
	if p.Dictionary != nil {
		d := dictionaryHealthDTO(*p.Dictionary)
		out.Dictionary = &d
	}
	return out
}

func (p *piiHealthDTO) toDomain() *ledger.PIIHealth {
	if p == nil {
		return nil
	}
	out := &ledger.PIIHealth{
		Classified: p.Classified, Unclassified: p.Unclassified, UnclassifiedNames: p.UnclassifiedNames,
		Review: p.Review, ReviewNames: p.ReviewNames,
	}
	if p.Dictionary != nil {
		d := ledger.DictionaryHealth(*p.Dictionary)
		out.Dictionary = &d
	}
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func healthFromDomain(h ledger.Health) healthDTO {
	out := healthDTO{
		Chain: chainDTO{Intact: h.Chain.Intact, BrokenAt: h.Chain.BrokenAt}, Head: headFromDomain(h.Head),
		Install: h.Install, PinSetAside: h.PinSetAside, PinMoved: h.PinMoved,
		Reinstalls: reinstallsFromDomain(h.Reinstalls), EarlierReinstalls: h.Reinstalls.Earlier,
		Uncovered: make([]uncoveredDTO, 0, len(h.Uncovered)), RLSBlind: h.RLSBlind,
		LastHeartbeat: h.LastHeartbeat, HeartbeatStale: h.HeartbeatStale, PII: piiHealthFromDomain(h.PII),
	}
	for _, u := range h.Uncovered {
		out.Uncovered = append(out.Uncovered, uncoveredDTO(u))
	}
	if h.DeadMan != nil {
		d := deadManDTO(*h.DeadMan)
		out.DeadMan = &d
	}
	return out
}

func (h healthDTO) toDomain() ledger.Health {
	out := ledger.Health{
		Chain: guard.ChainStatus{Intact: h.Chain.Intact, BrokenAt: h.Chain.BrokenAt}, Head: h.Head.toDomain(),
		Install: h.Install, PinSetAside: h.PinSetAside, PinMoved: h.PinMoved,
		Reinstalls: reinstallsToDomain(h.Reinstalls, h.EarlierReinstalls),
		RLSBlind:   h.RLSBlind, LastHeartbeat: h.LastHeartbeat, HeartbeatStale: h.HeartbeatStale,
		PII: h.PII.toDomain(),
	}
	for _, u := range h.Uncovered {
		out.Uncovered = append(out.Uncovered, guard.Uncovered(u))
	}
	if h.DeadMan != nil {
		d := ledger.DeadMan(*h.DeadMan)
		out.DeadMan = &d
	}
	return out
}

type changeListParams struct {
	Limit  int       `json:"limit"`
	Cursor string    `json:"cursor"`
	Sort   string    `json:"sort"`
	RunID  uuid.UUID `json:"runId"`
}

func changeParamsFromDomain(p ledger.ChangeListParams) changeListParams {
	return changeListParams{Limit: p.Limit, Cursor: p.Cursor, Sort: p.Sort, RunID: p.RunID}
}

func (p changeListParams) toDomain() ledger.ChangeListParams {
	out := ledger.ChangeListParams{Params: pagination.Params{Limit: p.Limit, Cursor: p.Cursor, Sort: p.Sort}, RunID: p.RunID}
	out.ApplyDefaultsAndClamp()
	return out
}

type changeDTO struct {
	ID           uuid.UUID       `json:"id"`
	At           time.Time       `json:"at"`
	Agent        string          `json:"agent"`
	RunID        uuid.NullUUID   `json:"runId"`
	TaskID       uuid.NullUUID   `json:"taskId"`
	Intent       string          `json:"intent"`
	Op           string          `json:"op"`
	Table        string          `json:"table"`
	Statement    string          `json:"statement"`
	Params       json.RawMessage `json:"params"`
	Rows         int             `json:"rows"`
	CascadedRows int             `json:"cascadedRows"`
	DurationMs   *int            `json:"durationMs"`
	Status       string          `json:"status"`
	Code         string          `json:"code"`
	Reason       string          `json:"reason"`
	ActorKind    string          `json:"actorKind"`
	RevertID     uuid.NullUUID   `json:"revertId"`
	RevertedBy   []uuid.UUID     `json:"revertedBy"`
	// LargeValues is set on agent reads only; the person reads in full.
	LargeValues []largevalue.Entry `json:"-"`
}

type pageDTO[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor"`
}

func mapPage[A, B any](p pagination.Page[A], f func(A) B) pageDTO[B] {
	out := pageDTO[B]{Items: make([]B, 0, len(p.Items)), NextCursor: p.NextCursor}
	for _, it := range p.Items {
		out.Items = append(out.Items, f(it))
	}
	return out
}

func mapSlice[A, B any](in []A, f func(A) B) []B {
	out := make([]B, 0, len(in))
	for _, it := range in {
		out = append(out, f(it))
	}
	return out
}

func changeFromDomain(c ledger.Change) changeDTO { return changeDTO(c) }
func (c changeDTO) toDomain() ledger.Change      { return ledger.Change(c) }

type rowChangesParams struct {
	ChangeIDs []uuid.UUID `json:"changeIds"`
}

type rowChangeDTO struct {
	Seq        int64           `json:"seq"`
	Table      string          `json:"table"`
	Op         string          `json:"op"`
	Key        map[string]any  `json:"key"`
	Before     map[string]any  `json:"before"`
	After      map[string]any  `json:"after"`
	Cascaded   bool            `json:"cascaded"`
	Redacted   bool            `json:"redacted"`
	Pruned     bool            `json:"pruned"`
	BasedOn    *ledger.BasedOn `json:"basedOn"`
	BlindWrite bool            `json:"blindWrite"`
	// LargeValues and the left-out flags are set on agent reads only.
	LargeValues                             []largevalue.Entry `json:"-"`
	KeyLeftOut, BeforeLeftOut, AfterLeftOut bool               `json:"-"`
	// Marks summarize the values over 1 MiB, for the CLI's text output.
	Marks largevalue.Marks `json:"marks"`
}

type rowChangesDTO struct {
	Rows map[uuid.UUID][]rowChangeDTO `json:"rows"`
}

func rowChangesFromDomain(m map[uuid.UUID][]ledger.RowChange) rowChangesDTO {
	out := rowChangesDTO{Rows: make(map[uuid.UUID][]rowChangeDTO, len(m))}
	for id, rows := range m {
		out.Rows[id] = mapSlice(rows, func(r ledger.RowChange) rowChangeDTO { return rowChangeDTO(r) })
	}
	return out
}

func (d rowChangesDTO) toDomain() map[uuid.UUID][]ledger.RowChange {
	out := make(map[uuid.UUID][]ledger.RowChange, len(d.Rows))
	for id, rows := range d.Rows {
		out[id] = mapSlice(rows, func(r rowChangeDTO) ledger.RowChange { return ledger.RowChange(r) })
	}
	return out
}

// passkeyDTO is a registered passkey: its public key only.
type passkeyDTO struct {
	CredentialID passkey.Bytes `json:"credentialId"`
	X            passkey.Bytes `json:"x"`
	Y            passkey.Bytes `json:"y"`
	SignCount    uint32        `json:"signCount"`
	RPID         string        `json:"rpId"`
	Origin       string        `json:"origin"`
	UserHandle   passkey.Bytes `json:"userHandle"`
	Label        string        `json:"label"`
	CreatedAt    time.Time     `json:"createdAt"`
	LastUsedAt   *time.Time    `json:"lastUsedAt"`
}

type passkeysDTO struct {
	Items []passkeyDTO `json:"items"`
}

func passkeyFromDomain(k ledger.Passkey) (passkeyDTO, error) {
	x, y, err := k.Credential.XY()
	if err != nil {
		return passkeyDTO{}, err
	}
	return passkeyDTO{
		CredentialID: k.Credential.ID, X: x, Y: y, SignCount: k.Credential.SignCount,
		RPID: k.Credential.Relying.RPID, Origin: k.Credential.Relying.Origin, UserHandle: k.Credential.UserHandle,
		Label: k.Label, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
	}, nil
}

func (k passkeyDTO) toDomain() (ledger.Passkey, error) {
	pub, err := passkey.PublicKeyFromXY(k.X, k.Y)
	if err != nil {
		return ledger.Passkey{}, fmt.Errorf("passkey %s: %w", k.CredentialID, err)
	}
	return ledger.Passkey{
		Credential: passkey.Credential{
			ID: k.CredentialID, PublicKey: pub, SignCount: k.SignCount,
			Relying: passkey.Relying{RPID: k.RPID, Origin: k.Origin}, UserHandle: k.UserHandle,
		},
		Label: k.Label, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
	}, nil
}

type approvalIDParams struct {
	ApprovalID uuid.UUID `json:"approvalId"`
}

type revertIDParams struct {
	RevertID uuid.UUID `json:"revertId"`
}

type approvalDTO struct {
	ID          uuid.UUID       `json:"id"`
	RunID       uuid.UUID       `json:"runId"`
	TaskID      uuid.NullUUID   `json:"taskId"`
	Intent      string          `json:"intent"`
	Statement   string          `json:"statement"`
	Params      json.RawMessage `json:"params"`
	Assigned    []string        `json:"assigned"`
	Rows        int             `json:"rows"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"createdAt"`
	ExpiresAt   time.Time       `json:"expiresAt"`
	ApprovedAt  *time.Time      `json:"approvedAt"`
	BindingText string          `json:"bindingText"`
	Lines       []string        `json:"lines"`
	// LargeValues is set on agent reads only; the person reads in full.
	LargeValues []largevalue.Entry `json:"-"`
}

type assertionDTO struct {
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

func assertionFromDomain(a passkey.Assertion) assertionDTO {
	return assertionDTO{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}
}

func (a assertionDTO) toDomain() passkey.Assertion {
	return passkey.Assertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}
}

type submitApprovalParams struct {
	ApprovalID uuid.UUID    `json:"approvalId"`
	Assertion  assertionDTO `json:"assertion"`
}

type submittedDTO struct {
	ApprovedAt time.Time `json:"approvedAt"`
}

type progressDTO struct {
	Restored int `json:"restored"`
	Skipped  int `json:"skipped"`
	Pending  int `json:"pending"`
}

type revertDTO struct {
	ID          uuid.UUID   `json:"id"`
	Status      string      `json:"status"`
	Scope       string      `json:"scope"`
	ScopeID     uuid.UUID   `json:"scopeId"`
	Intent      string      `json:"intent"`
	Rows        int         `json:"rows"`
	Skipped     int         `json:"skipped"`
	ExpiresAt   time.Time   `json:"expiresAt"`
	BindingText string      `json:"bindingText"`
	Lines       []string    `json:"lines"`
	Batched     bool        `json:"batched"`
	SignedAt    *time.Time  `json:"signedAt"`
	ApplyBy     *time.Time  `json:"applyBy"`
	Batches     int         `json:"batches"`
	Progress    progressDTO `json:"progress"`
	ChangeID    *uuid.UUID  `json:"changeId"`
}

func revertFromDomain(r ledger.Revert) revertDTO {
	return revertDTO{
		ID: r.ID, Status: r.Status, Scope: r.Scope, ScopeID: r.ScopeID, Intent: r.Intent, Rows: r.Rows, Skipped: r.Skipped,
		ExpiresAt: r.ExpiresAt, BindingText: r.BindingText, Lines: r.Lines, Batched: r.Batched, SignedAt: r.SignedAt,
		ApplyBy: r.ApplyBy, Batches: r.Batches, Progress: progressDTO(r.Progress), ChangeID: r.ChangeID,
	}
}

func (r revertDTO) toDomain() ledger.Revert {
	return ledger.Revert{
		ID: r.ID, Status: r.Status, Scope: r.Scope, ScopeID: r.ScopeID, Intent: r.Intent, Rows: r.Rows, Skipped: r.Skipped,
		ExpiresAt: r.ExpiresAt, BindingText: r.BindingText, Lines: r.Lines, Batched: r.Batched, SignedAt: r.SignedAt,
		ApplyBy: r.ApplyBy, Batches: r.Batches, Progress: ledger.RevertProgress(r.Progress), ChangeID: r.ChangeID,
	}
}

type scopeParams struct {
	Scope  revert.Scope `json:"scope"`
	ID     uuid.UUID    `json:"id"`
	Runs   []uuid.UUID  `json:"runs,omitempty"`
	Tables []string     `json:"tables,omitempty"`
	Intent string       `json:"intent,omitempty"`
}

func scopeParamsFromDomain(s guard.RevertScope, intent string) scopeParams {
	return scopeParams{Scope: s.Kind, ID: s.ID, Runs: s.Runs, Tables: s.Tables, Intent: intent}
}

// rescopeParams is RESCOPE_REVERT's: the revert keeps its scope kind and
// id, and runs and tables narrow it (nil for all).
type rescopeParams struct {
	RevertID uuid.UUID   `json:"revertId"`
	Runs     []uuid.UUID `json:"runs,omitempty"`
	Tables   []string    `json:"tables,omitempty"`
}

type rejectParams struct {
	RevertID uuid.UUID `json:"revertId"`
	Note     string    `json:"note,omitempty"`
}

func (p scopeParams) validate() error {
	switch p.Scope {
	case revert.ScopeChange, revert.ScopeRun, revert.ScopeTask:
	default:
		return fmt.Errorf("scope must be CHANGE, RUN or TASK, not %q", p.Scope)
	}
	if p.ID == uuid.Nil {
		return fmt.Errorf("id is required")
	}
	return nil
}

func (p scopeParams) toDomain() guard.RevertScope {
	return guard.RevertScope{Kind: p.Scope, ID: p.ID, Runs: p.Runs, Tables: p.Tables}
}

type previewDTO struct {
	Lines []string `json:"lines"`
}

type preparedDTO struct {
	RevertID    uuid.UUID `json:"revertId"`
	BindingText string    `json:"bindingText"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Lines       []string  `json:"lines"`
	Batched     bool      `json:"batched"`
}

type applyRevertParams struct {
	RevertID  uuid.UUID    `json:"revertId"`
	Assertion assertionDTO `json:"assertion"`
}

type revertLineParams struct {
	RevertID uuid.UUID `json:"revertId"`
	Outcome  string    `json:"outcome"`
	Limit    int       `json:"limit"`
	Cursor   string    `json:"cursor"`
}

func revertLineParamsFromDomain(p ledger.RevertLineParams) revertLineParams {
	return revertLineParams{RevertID: p.RevertID, Outcome: p.Outcome, Limit: p.Limit, Cursor: p.Cursor}
}

func (p revertLineParams) toDomain() ledger.RevertLineParams {
	return ledger.RevertLineParams{Params: pagination.Params{Limit: p.Limit, Cursor: p.Cursor}, RevertID: p.RevertID, Outcome: p.Outcome}
}

type revertLineDTO struct {
	No       int    `json:"no"`
	Text     string `json:"text"`
	Outcome  string `json:"outcome"`
	Conflict string `json:"conflict"`
	SQLState string `json:"sqlState"`
	Batch    *int   `json:"batch"`
}
