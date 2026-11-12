package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/vault"
)

// The revert page's scope route (CONTRACT.md, Revert, Rescope, widen and
// reject; Local pages, POST /api/v1/reverts/{revertId}/scope): the person
// narrows the agent's proposal, or widens it with a passkey proof bound to
// a new link secret the page made. The engine derives the rescope key from
// that secret and sends Postgres only the key and the proof; the secret
// itself never reaches Postgres. Postgres decides every check.

// RescopeTimeout caps one rescope or reset (N12-R9): past it Postgres
// cancels it and nothing changes.
const RescopeTimeout = guard.MCPPrepareTimeout

// ScopeRequest is the body of POST …/scope (revert-scope-request.schema.json).
// Proof and NewSecret come together: a widen.
type ScopeRequest struct {
	Select    revert.Select `json:"select"`
	Proof     *ScopeProof   `json:"proof,omitempty"`
	NewSecret string        `json:"newSecret,omitempty"`
}

// ScopeProof is the person's widen proof: a passkey assertion over
// revert.RescopeChallenge, its fields base64url.
type ScopeProof struct {
	CredentialID      passkey.Bytes `json:"credentialId"`
	AuthenticatorData passkey.Bytes `json:"authenticatorData"`
	ClientDataJSON    passkey.Bytes `json:"clientDataJson"`
	Signature         passkey.Bytes `json:"signature"`
}

func (p ScopeProof) assertion() passkey.Assertion {
	return passkey.Assertion{
		CredentialID: p.CredentialID, AuthenticatorData: p.AuthenticatorData,
		ClientDataJSON: p.ClientDataJSON, Signature: p.Signature,
	}
}

// ScopeResponse is the 200 answer of POST …/scope
// (revert-scope-response.schema.json): the rebuilt request, and the catalog
// for a proven widen or a narrow under its scope token.
type ScopeResponse struct {
	Request revert.Request       `json:"request"`
	Catalog *guard.RevertCatalog `json:"catalog,omitempty"`
}

// rescoped is what the engine holds in memory for a revert the person
// rescoped through it: never written to stateDir, gone after a restart
// (owner, Q13). Lines and catalog after a widen hold other agents' values,
// served only to a request carrying the rotated link.
type rescoped struct {
	// link is sha256 of the link secret the state belongs to: the rotated
	// one after a widen, the live one otherwise.
	link    [sha256.Size]byte
	token   []byte
	request revert.Request
	catalog *guard.RevertCatalog
	expires time.Time
}

// rescopes are a service's rescoped reverts, by revert id.
type rescopes struct {
	mu   sync.Mutex
	byID map[uuid.UUID]rescoped
}

func newRescopes() *rescopes { return &rescopes{byID: map[uuid.UUID]rescoped{}} }

// get is id's state when it belongs to the link secret and has not
// expired.
func (r *rescopes) get(id uuid.UUID, secret string, now time.Time) (rescoped, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.byID[id]
	if ok && !now.Before(st.expires) {
		delete(r.byID, id)
		return rescoped{}, false
	}
	hash := sha256.Sum256([]byte(secret))
	if !ok || subtle.ConstantTimeCompare(hash[:], st.link[:]) != 1 {
		return rescoped{}, false
	}
	return st, true
}

func (r *rescopes) put(id uuid.UUID, st rescoped) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[id] = st
}

func (r *rescopes) drop(id uuid.UUID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byID, id)
}

// RescopeRevert changes the scope of a revert this agent's role prepared,
// for the person on the revert page that holds secret, the revert's live
// link secret (the pages checked it). Without a proof it is a narrow: the
// engine adds the scope token it holds for this link, if any. With a proof
// and the page's new secret it is a widen: on success the revert's link is
// rotated to that secret, and the token, lines and catalog Postgres
// returned are kept in memory for it.
func (s *Service) RescopeRevert(ctx context.Context, id uuid.UUID, secret string, in ScopeRequest) (ScopeResponse, error) {
	r, err := s.openRevert(ctx, id, nil)
	if err != nil {
		return ScopeResponse{}, err
	}
	req := guard.RescopeRequest{RevertID: id, Select: in.Select}
	widen := in.Proof != nil
	if widen {
		raw, err := links.DecodeSecret(in.NewSecret)
		if err != nil {
			return ScopeResponse{}, &ArgumentError{Message: "newSecret must be 16 random bytes, base64url without padding"}
		}
		key, err := revert.RescopeKey(raw)
		clear(raw)
		if err != nil {
			return ScopeResponse{}, err
		}
		as := in.Proof.assertion()
		req.Proof, req.RescopeKey = &as, key
	}
	st, held := s.rescopes.get(id, secret, s.Now())
	if !widen && held {
		req.Token = st.token
	}
	out, err := s.Reverts.RescopeRevert(ctx, req, RescopeTimeout)
	if err != nil {
		return ScopeResponse{}, s.rescopeError(ctx, r, err)
	}
	ids, err := s.credentialIDs(ctx)
	if err != nil {
		return ScopeResponse{}, err
	}
	next := rescoped{link: sha256.Sum256([]byte(secret)), token: req.Token, catalog: out.Catalog, expires: out.ExpiresAt,
		request: revert.Request{RevertID: id, Binding: out.BindingText, Lines: out.Lines, RescopeNonce: out.RescopeNonce, CredentialIDs: ids}}
	if widen {
		next.link, next.token = sha256.Sum256([]byte(in.NewSecret)), out.ScopeToken
	}
	if err := s.moveLink(ctx, id, in, out.ExpiresAt); err != nil {
		return ScopeResponse{}, err
	}
	s.rescopes.put(id, next)
	return ScopeResponse{Request: next.request, Catalog: out.Catalog}, nil
}

// moveLink gives the revert's link the rescoped revert's expiry, and on a
// widen rotates it to the page's new secret.
func (s *Service) moveLink(ctx context.Context, id uuid.UUID, in ScopeRequest, expires time.Time) error {
	if in.Proof == nil {
		s.extendLink(ctx, id, expires)
		return nil
	}
	return s.rotateLink(ctx, id, in.NewSecret, expires)
}

// rotateLink moves the revert's link to the page's new secret: the old one
// stops working at once (the agent's link is dead). Inside a Vault session
// the session moves to the new token and stays open, the old token's other
// sessions end, and the new token is registered so a later session can
// open with the new secret.
func (s *Service) rotateLink(ctx context.Context, id uuid.UUID, secret string, expires time.Time) error {
	rot, err := s.Links.Rotate(id, secret, expires)
	if err != nil {
		return err
	}
	if !rot.Relay {
		return nil
	}
	vault.RotateSession(ctx, rot.Token)
	s.registerRelay(ctx, id, rot.Token, expires)
	return nil
}

// extendLink moves the live link's expiry to the revert's new one (every
// rescope restarts the hour, owner Q12), registering a relay link again
// with it. A failure only shortens the link: it is logged.
func (s *Service) extendLink(ctx context.Context, id uuid.UUID, expires time.Time) {
	l, relay, err := s.Links.Extend(id, expires)
	if err != nil {
		s.Log.Warn("extend a rescoped revert's link", "id", id, "err", err)
		return
	}
	if relay {
		s.registerRelay(ctx, id, l.Token, expires)
	}
}

// registerRelay registers token with the Vault until expires. A refusal
// leaves the open session working; a new session for it is refused until
// the engine registers its links again after its next READY.
func (s *Service) registerRelay(ctx context.Context, id uuid.UUID, token channel.LinkToken, expires time.Time) {
	if err := s.Relay.Register(ctx, token, expires); err != nil {
		s.Log.Warn("the Vault did not register a rotated revert link", "id", id, "err", err)
	}
}

// rescopeError is the page's answer to a rescope Postgres refused, in the
// contract's check order: a descriptor bad on its shape alone, or outside
// the scope once proven, is INVALID_ARGUMENT; every proof or token
// failure is one REVERT_INVALID whatever its cause; a rescope past
// RescopeTimeout is QUERY_TIMEOUT TIME_LIMIT.
func (s *Service) rescopeError(ctx context.Context, r ledger.Revert, err error) error {
	if _, hint, ok := guard.ScopeRefusal(err); ok {
		return &ArgumentError{Message: "the scope was refused: " + hint}
	}
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		return err
	}
	code, _ := guard.CodeOf(err)
	switch {
	case code == guard.CodeRevertInvalid && pe.Detail == guard.RevertWidenRefused:
		return widenRefused()
	case code == guard.CodeRevertExpired:
		return s.revertExpired(r)
	case pe.Code == sqlStateQueryCanceled && ctx.Err() == nil:
		return rescopeTimeout()
	}
	return err
}

// PageError is an answer meant for the revert page as it is: the pages
// answer it without the agent's catalog, since no agent tool returns it.
type PageError struct{ *mcp.ToolError }

func (e *PageError) Unwrap() error { return e.ToolError }

// widenRefused is every failed proof or token check (CONTRACT.md, check
// order 3): one fixed answer, so the agent holding the link learns nothing
// about other agents' runs or tables from it.
func widenRefused() error {
	return &PageError{&mcp.ToolError{Code: CodeRevertInvalid,
		Message: "the scope change was refused: it needs the person's passkey proof, or the page that proved one; nothing changed",
		PersonMessage: "This scope change was refused, and nothing changed. To include other agents' changes, choose them " +
			"again on this page and confirm with your passkey."}}
}

// rescopeTimeout is a rescope that ran past RescopeTimeout (N12-R9).
func rescopeTimeout() error {
	return &PageError{&mcp.ToolError{Code: CodeQueryTimeout, Reason: ReasonTimeLimit,
		Message: "the scope change took longer than 100 seconds and was stopped; nothing changed",
		PersonMessage: "Changing the scope took longer than 100 seconds and was stopped. Nothing changed. " +
			"Choose fewer agents, runs or tables, or try again."}}
}

// widenAgain is a widened revert whose lines this engine no longer holds:
// it restarted since the person widened it (owner, Q13).
func widenAgain() error {
	return &PageError{&mcp.ToolError{Code: CodeRevertInvalid,
		Message: "the engine restarted since the person widened this revert, and holds its lines in memory only",
		PersonMessage: "The scope you chose on this page is no longer held by the engine (it restarted). Include other " +
			"agents' changes again to see the lines, or ask the agent for a new link to its own proposal."}}
}

// resetToProposal puts a widened revert back to the agent's proposal for
// its reissueLink (owner, Q8): Postgres drops the person's scope and
// records REVERT_RESET, the person's link is revoked and kept so the page
// can say the agent reset it (LINK_RESET), and the lines held in memory
// go. The caller issues the new link.
func (s *Service) resetToProposal(ctx context.Context, r ledger.Revert) (ledger.Revert, error) {
	out, err := s.Reverts.ResetRevert(ctx, r.ID, RescopeTimeout)
	if err != nil {
		return ledger.Revert{}, err
	}
	s.rescopes.drop(r.ID)
	if err := s.Links.Reset(r.ID, out.ExpiresAt); err != nil {
		return ledger.Revert{}, err
	}
	return s.Reverts.FindRevert(ctx, r.ID)
}

// CheckResetLink reports whether secret is a link of revert id that the
// agent's reset revoked (NOT_FOUND reason LINK_RESET on the pages).
func (s *Service) CheckResetLink(id uuid.UUID, secret string) bool {
	return s.Links.WasReset(id, secret)
}
