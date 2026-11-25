package storeproof_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/agentstore"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule/textruletest"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// The approval's ports: Records, Holds and Proofs. The store holds a write
// with the request as the agent sent it, checks the person's assertion
// itself and keeps the held write's state.

// memApproval is one held write.
type memApproval struct {
	rec action.Approval
}

// memPagesOrigin is the origin of the pages the person's passkey signs on.
var memPagesOrigin = strings.TrimSuffix(links.DefaultLocal, "/")

// memExpiry is how long a held write or a revert waits for the person.
const memExpiry = time.Hour

// expiresAt is an expiry in the text rules' precision.
func expiresAt() time.Time {
	return time.Now().Add(memExpiry).UTC().Truncate(time.Microsecond)
}

// personAssertion is the person's passkey assertion over a binding: the
// test's stand-in for a signature, which the store checks itself.
func personAssertion(binding string) passkey.Assertion {
	sum := sha256.Sum256([]byte("the person's passkey signs " + binding))
	return passkey.Assertion{
		CredentialID: passkey.Bytes("person-passkey"), AuthenticatorData: passkey.Bytes("authenticator"),
		ClientDataJSON: passkey.Bytes(`{"type":"webauthn.get"}`), Signature: sum[:],
	}
}

// Records (approval and revert).

func (s *memStore) FindApproval(_ context.Context, id uuid.UUID) (action.Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("FindApproval")
	a, ok := s.approvals[id]
	if !ok {
		return action.Approval{}, &action.ApprovalRefusalError{Reason: action.ApprovalNotFound, Err: fmt.Errorf("no held write %s of %s", id, memAgent)}
	}
	return a.rec, nil
}

func (s *memStore) ListApprovals(_ context.Context, p action.ApprovalListParams) (pagination.Page[action.Approval], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("ListApprovals")
	var out pagination.Page[action.Approval]
	for _, a := range s.approvals {
		open := a.rec.Status == action.ApprovalPending || a.rec.Status == action.ApprovalApproved
		if open && (p.RunID == uuid.Nil || a.rec.RunID == p.RunID) {
			out.Items = append(out.Items, a.rec)
		}
	}
	return out, nil
}

func (s *memStore) Passkeys(context.Context) ([]passkey.Credential, error) {
	return []passkey.Credential{{ID: []byte("person-passkey"), Relying: passkey.Relying{Origin: memPagesOrigin}}}, nil
}

func (s *memStore) RevealNonce(_ context.Context, kind string, id uuid.UUID) ([]byte, error) {
	sum := sha256.Sum256([]byte("reveal " + kind + " " + id.String()))
	return sum[:], nil
}

// Holds.

// heldLines are the preview lines of an update: one per document, in the
// store's kind, verb and resource name.
func (s *memStore) heldLines(r memRequest, params []any) ([]string, []string) {
	assigned := slices.Sorted(maps.Keys(r.Set))
	docs := s.match(r, params)
	lines := make([]string, 0, len(docs))
	for _, d := range docs {
		old := map[string]any{}
		for _, f := range assigned {
			old[f] = d[f]
		}
		lines = append(lines, textruletest.MustText(approval.Line{
			Op: approval.OpUpdate, Key: rawJSON(map[string]any{"_id": d["_id"]}), Old: rawJSON(old), Set: rawJSON(r.Set),
			Shape: approval.ShapeRecord, Store: approval.LineStore{Kind: string(memKind), Verb: memVerbUpdate}, Resource: r.Update,
		}))
	}
	return assigned, lines
}

func (s *memStore) Preview(_ context.Context, _ action.Intent, req agentstore.Request) (action.HeldPreview, error) {
	s.saw("Preview", req.Text)
	r, err := parseRequest(req.Text)
	if err != nil {
		return action.HeldPreview{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("Preview")
	assigned, lines := s.heldLines(r, req.Params)
	return action.HeldPreview{Assigned: assigned, Lines: lines}, nil
}

func (s *memStore) Hold(_ context.Context, in action.Intent, hr action.HoldRequest) (action.Held, error) {
	s.saw("Hold", hr.Request.Text)
	params := make([]json.RawMessage, 0, len(hr.Request.Params))
	for _, p := range hr.Request.Params {
		raw, err := json.Marshal(p)
		if err != nil {
			return action.Held{}, err
		}
		params = append(params, raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("Hold")
	id := s.nextID()
	expires := expiresAt()
	binding, err := textruletest.Text(approval.Binding{
		Kind: approval.KindApprove, ApprovalID: id, Store: approval.BindingStore{Kind: string(memKind), Name: memDatabase},
		Agent: approval.AgentName(memAgent), RunID: in.RunID, Intent: in.Text,
		Request:        approval.HeldRequest{Kind: memRequestKind, Statement: hr.Request.Text, Params: params},
		AssignedFields: hr.Assigned, Rows: len(hr.Lines), RowsHash: approval.RowsHash(hr.Lines), ExpiresAt: expires,
	})
	if err != nil {
		return action.Held{}, err
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return action.Held{}, err
	}
	s.approvals[id] = &memApproval{rec: action.Approval{
		ID: id, RunID: in.RunID, TaskID: uuid.NullUUID{UUID: in.TaskID, Valid: in.TaskID != uuid.Nil}, Intent: in.Text,
		Request:  action.HeldRequest{Kind: memRequestKind, Text: hr.Request.Text, Params: rawParams},
		Assigned: hr.Assigned, Rows: len(hr.Lines), Status: action.ApprovalPending, CreatedAt: time.Now().UTC(),
		ExpiresAt: expires, BindingText: binding, Lines: hr.Lines,
	}}
	return action.Held{ApprovalID: id, BindingText: binding, ExpiresAt: expires}, nil
}

// Proofs.

// postgresBadSignature is the refusal the Postgres adapter maps the
// guard's answer to a signature it does not accept to (submit_approval's
// detail in 005_approvals.sql).
func postgresBadSignature() *action.StoreError {
	return postgresAnswer(&pgconn.PgError{Code: "BS005", Message: "APPROVAL_INVALID", Detail: "bad passkey signature"})
}

func (s *memStore) SubmitApproval(_ context.Context, id uuid.UUID, a passkey.Assertion) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("SubmitApproval")
	ap, ok := s.approvals[id]
	if !ok {
		return time.Time{}, &action.ApprovalRefusalError{Reason: action.ApprovalNotFound, Err: fmt.Errorf("no held write %s", id)}
	}
	if !slices.Equal(a.Signature, personAssertion(ap.rec.BindingText).Signature) {
		if s.asPostgres {
			return time.Time{}, postgresBadSignature()
		}
		msg := "the passkey's signature does not match the held write"
		return time.Time{}, &action.StoreError{
			Code: action.CodeApprovalInvalid, Reason: action.ReasonBadSignature, StoreCode: codeSignature, Message: msg, Err: errors.New(msg),
		}
	}
	now := time.Now().UTC()
	ap.rec.Status, ap.rec.ApprovedAt = action.ApprovalApproved, &now
	return now, nil
}

// errRevealUnsupported is the store's answer to a reveal: the proof never
// reaches it while the service refuses the binding first.
var errRevealUnsupported = errors.New("the memory store under test reveals no held rows")

func (s *memStore) RevealHeld(_ context.Context, _ uuid.UUID, held action.HeldRun, _ passkey.Assertion, _ []byte) ([]approval.RevealedRow, error) {
	s.saw("RevealHeld", held.Request.Statement)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("RevealHeld")
	return nil, errRevealUnsupported
}
