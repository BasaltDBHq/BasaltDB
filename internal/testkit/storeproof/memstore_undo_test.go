package storeproof_test

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule/textruletest"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// The revert's ports: Records, Undo and Proofs, over the changes the
// agent's writes recorded. A revert line puts a document's earlier version
// back unless someone changed it after the agent (people win).

// memVerbRestore is the store's own word for a revert line that puts a
// document back.
const memVerbRestore = "replaceOne"

// memResourceName is the store's form of a resource name.
var memResourceName = regexp.MustCompile(`^[a-z]+/[a-z]+$`)

// memFilterNameDetail is the store's text for a resource name it cannot
// use.
const memFilterNameDetail = "resources are namespace/collection names, like shop/customers"

// memLine is one line of a revert: its signed text, and what the store
// needs to apply it.
type memLine struct {
	no            int
	text          string
	resource, key string
	// set is what the revert puts back (nil deletes the document);
	// version is the document's version the line was prepared over.
	set     map[string]any
	version int
	restore bool
	outcome string
	// conflict and code say why a line was skipped, code in the store's
	// own words.
	conflict, code string
	batch          *int
}

type memRevert struct {
	rec   action.Revert
	lines []memLine
}

// postgresRevertRefusals are the refusals the Postgres adapter maps the
// guard's answers to: the reason, the guard's text and the SQLSTATE.
var postgresRevertRefusals = []postgresRefusal{
	{reason: action.RevertNotFound},
	{reason: action.RevertNotOwnRun, detail: "the run is not one of yours"},
	{reason: action.RevertFilter, detail: "public.ghost has no change of yours in this scope"},
	{reason: action.RevertFilterName, detail: "leads is not a schema.table name"},
	{reason: action.RevertRowsChanged, detail: "rows changed since the preview; nothing was reverted, prepare the revert again"},
	{reason: action.RevertTimedOut, code: "57014"},
}

type postgresRefusal struct {
	reason       action.RevertReason
	detail, code string
}

// postgresRefusalOf is the Postgres adapter's refusal for reason.
func postgresRefusalOf(reason action.RevertReason) postgresRefusal {
	i := slices.IndexFunc(postgresRevertRefusals, func(p postgresRefusal) bool { return p.reason == reason })
	if i < 0 {
		panic("no Postgres refusal for " + reason)
	}
	return postgresRevertRefusals[i]
}

// refuseRevert is the store's refusal of a revert call for reason, with its
// own text and code, or Postgres's.
func (s *memStore) refuseRevert(reason action.RevertReason, detail, code string) error {
	if s.asPostgres {
		pg := postgresRefusalOf(reason)
		detail, code = pg.detail, pg.code
	}
	return &action.RevertRefusalError{
		Reason: reason, Detail: detail, StoreCode: code,
		Err: fmt.Errorf("store refused the revert call: %s", cmp.Or(detail, code, string(reason))),
	}
}

// slowRun is a run whose revert the store stops at its time limit.
var slowRun = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a3")

// selectChanges are the agent's changes in scope, narrowed to its
// resources. The store checks the names: their form, and that the agent
// wrote each one in the scope.
func (s *memStore) selectChanges(scope action.Scope) ([]change, error) {
	for _, name := range scope.Tables {
		if !memResourceName.MatchString(name) {
			return nil, s.refuseRevert(action.RevertFilterName, memFilterNameDetail, "")
		}
	}
	var own []change
	for _, c := range s.changes {
		in := (scope.Kind == revert.ScopeRun && c.run == scope.ID) || (scope.Kind == revert.ScopeChange && c.id == scope.ID)
		if in && c.agent == memAgent {
			own = append(own, c)
		}
	}
	if len(own) == 0 {
		return nil, s.refuseRevert(action.RevertNotOwnRun, fmt.Sprintf("run %s has no change of %s", scope.ID, memAgent), "")
	}
	if scope.Tables == nil {
		return own, nil
	}
	written := map[string]bool{}
	for _, c := range own {
		written[c.resource] = true
	}
	for _, name := range scope.Tables {
		if !written[name] {
			return nil, s.refuseRevert(action.RevertFilter, name+" has no change of yours in this run", "")
		}
	}
	return slices.DeleteFunc(own, func(c change) bool { return !slices.Contains(scope.Tables, c.resource) }), nil
}

// planLines are the lines that put back what changes changed, one per
// document, in resource and key order: the document as it was before the
// agent's first change, unless someone changed it after the agent's last.
func (s *memStore) planLines(changes []change) []memLine {
	type target struct{ resource, key string }
	first, last, ids := map[target]change{}, map[target]change{}, map[target][]uuid.UUID{}
	for _, c := range changes {
		t := target{c.resource, c.key}
		if _, ok := first[t]; !ok {
			first[t] = c
		}
		last[t], ids[t] = c, append(ids[t], c.id)
	}
	order := slices.SortedFunc(maps.Keys(first), func(a, b target) int {
		return cmp.Or(strings.Compare(a.resource, b.resource), strings.Compare(a.key, b.key))
	})
	out := make([]memLine, 0, len(order))
	for _, t := range order {
		f, l, cur := first[t], last[t], s.docs[t.resource][t.key]
		// The agent's language only updates documents: every line puts one
		// back. (The revert domain's own object store covers inserts,
		// deletes and a taken key.)
		line := revert.Line{
			Op: approval.OpUpdate, Key: rawJSON(map[string]any{"_id": t.key}), Now: rawJSON(cur.doc), Set: rawJSON(f.before),
			Shape: approval.ShapeRecord, Store: revert.LineStore{Kind: string(memKind), Verb: memVerbRestore},
			Resource: t.resource, Action: revert.ActionRestore, ChangeIDs: ids[t],
		}
		ml := memLine{resource: t.resource, key: t.key, set: f.before, version: l.version, restore: true}
		if cur.version != l.version {
			ml.conflict, ml.restore, line.Action = revert.ConflictChangedAfter, false, revert.ActionSkip
			line.Conflict = &ml.conflict
		}
		ml.text = textruletest.MustText(line)
		out = append(out, ml)
	}
	return out
}

func lineHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// Records.

func (s *memStore) FindRevert(_ context.Context, id uuid.UUID) (action.Revert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("FindRevert")
	r, ok := s.reverts[id]
	if !ok {
		return action.Revert{}, s.refuseRevert(action.RevertNotFound, "", "")
	}
	out := r.rec
	out.Lines = slices.Clone(r.rec.Lines)
	return out, nil
}

func (s *memStore) RevertLines(_ context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("RevertLines")
	r, ok := s.reverts[p.RevertID]
	if !ok {
		return pagination.Page[action.RevertLine]{}, s.refuseRevert(action.RevertNotFound, "", "")
	}
	after := int64(0)
	if p.Cursor != "" {
		var err error
		if after, err = pagination.DecodeSeqCursor(p.Cursor); err != nil {
			return pagination.Page[action.RevertLine]{}, err
		}
	}
	var out pagination.Page[action.RevertLine]
	for _, l := range r.lines {
		if int64(l.no) <= after || (p.Outcome != "" && l.outcome != p.Outcome) {
			continue
		}
		if len(out.Items) == p.Limit {
			out.NextCursor = pagination.EncodeSeqCursor(int64(out.Items[len(out.Items)-1].No))
			break
		}
		out.Items = append(out.Items, action.RevertLine{No: l.no, Text: l.text, Outcome: l.outcome, Conflict: l.conflict, StoreCode: l.code, Batch: l.batch})
	}
	return out, nil
}

func (s *memStore) ListOpenReverts(context.Context, action.RevertListParams) (pagination.Page[action.Revert], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("ListOpenReverts")
	var out pagination.Page[action.Revert]
	for _, r := range s.reverts {
		if r.rec.Status == action.RevertPending || r.rec.Status == action.RevertApplying {
			out.Items = append(out.Items, r.rec)
		}
	}
	return out, nil
}

func (s *memStore) RevertedBy(context.Context, action.Scope) (uuid.UUID, error) { return uuid.Nil, nil }

func (s *memStore) HasChange(_ context.Context, id uuid.UUID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.changes, func(c change) bool { return c.id == id && c.agent == memAgent }), nil
}

func (s *memStore) HasTaskRun(context.Context, uuid.UUID) (bool, error) { return false, nil }

func (s *memStore) RevertNonce(_ context.Context, id uuid.UUID) ([]byte, error) {
	sum := sha256.Sum256([]byte("rescope " + id.String()))
	return sum[:], nil
}

// Undo.

func (s *memStore) PreviewRevert(_ context.Context, scope action.Scope, after string, limit int) (action.PreviewPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("PreviewRevert")
	if scope.ID == slowRun {
		return action.PreviewPage{}, s.refuseRevert(action.RevertTimedOut, "", codeDeadline)
	}
	changes, err := s.selectChanges(scope)
	if err != nil {
		return action.PreviewPage{}, err
	}
	lines := s.planLines(changes)
	out := action.PreviewPage{Lines: len(lines), CursorFound: after == ""}
	start := 0
	for i, l := range lines {
		if l.restore {
			out.Restore++
		}
		if after != "" && lineHash(l.text) == after {
			start, out.CursorFound = i+1, true
		}
	}
	end := min(start+limit, len(lines))
	for _, l := range lines[start:end] {
		out.Page = append(out.Page, action.PreviewLine{Text: l.text, Hash: lineHash(l.text)})
	}
	out.More = end < len(lines)
	return out, nil
}

func (s *memStore) PrepareRevert(_ context.Context, scope action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("PrepareRevert")
	s.prepareLimits = append(s.prepareLimits, timeout)
	if scope.ID == slowRun {
		return action.PreparedRevert{}, s.refuseRevert(action.RevertTimedOut, "", codeDeadline)
	}
	changes, err := s.selectChanges(scope)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	lines := s.planLines(changes)
	texts, restore := make([]string, 0, len(lines)), 0
	for i := range lines {
		lines[i].no, lines[i].outcome = i+1, guardmodel.OutcomePending
		texts = append(texts, lines[i].text)
		if lines[i].restore {
			restore++
		}
	}
	if restore == 0 {
		return action.PreparedRevert{}, s.refuseRevert(action.RevertNothing, "every document changed after the agent", "")
	}
	id := s.nextID()
	b := revert.Binding{
		Kind: revert.KindRevert, RevertID: id, Store: approval.BindingStore{Kind: string(memKind), Name: memDatabase},
		Select: revert.Select{Scope: scope.Kind, ScopeID: scope.ID, Agents: []string{approval.AgentName(memAgent)}, Runs: scope.Runs, Resources: scope.Tables},
		Intent: intent, Rows: restore, Skipped: len(lines) - restore, RowsHash: approval.RowsHash(texts),
		ExpiresAt: expiresAt(), RequestedBy: approval.AgentName(memAgent),
	}
	shown := texts
	if len(texts) > revert.MaxLines {
		if shown, err = reverttest.Sample(texts); err != nil {
			return action.PreparedRevert{}, err
		}
		b.Batched, b.SampleHash = true, approval.RowsHash(shown)
	}
	binding, err := textruletest.Text(b)
	if err != nil {
		return action.PreparedRevert{}, err
	}
	s.reverts[id] = &memRevert{lines: lines, rec: action.Revert{
		ID: id, Status: action.RevertPending, Scope: string(scope.Kind), ScopeID: scope.ID, Intent: intent,
		Rows: b.Rows, Skipped: b.Skipped, ExpiresAt: b.ExpiresAt, BindingText: binding, Lines: shown,
		Batched: b.Batched, CreatedAt: time.Now().UTC(),
	}}
	return action.PreparedRevert{RevertID: id, BindingText: binding, ExpiresAt: b.ExpiresAt, Batched: b.Batched, LineCount: len(lines)}, nil
}

var errUnsupported = errors.New("the memory store under test does not reset, rescope, reject or reveal a revert")

func (s *memStore) ResetRevert(context.Context, uuid.UUID, time.Duration) (action.RescopedRevert, error) {
	return action.RescopedRevert{}, errUnsupported
}

// applyLine applies one line: the document goes back to its earlier
// version, unless someone changed it since the line was prepared.
func (s *memStore) applyLine(l *memLine, batch int) {
	if batch > 0 {
		l.batch = &batch
	}
	if !l.restore {
		l.outcome = guardmodel.OutcomeSkipped
		return
	}
	if s.docs[l.resource][l.key].version != l.version {
		l.outcome, l.conflict = guardmodel.OutcomeSkipped, revert.ConflictChangedAfter
		return
	}
	s.put(l.resource, l.key, l.set)
	l.outcome = guardmodel.OutcomeRestored
}

func (r *memRevert) progress() {
	r.rec.Progress = action.RevertProgress{}
	for _, l := range r.lines {
		switch l.outcome {
		case guardmodel.OutcomeRestored:
			r.rec.Progress.Restored++
		case guardmodel.OutcomeSkipped:
			r.rec.Progress.Skipped++
		default:
			r.rec.Progress.Pending++
		}
	}
}

func (s *memStore) ApplyRevertBatch(_ context.Context, id uuid.UUID, nos []int) (action.BatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("ApplyRevertBatch")
	r, ok := s.reverts[id]
	if !ok {
		return action.BatchResult{}, s.refuseRevert(action.RevertNotFound, "", "")
	}
	if r.rec.Status != action.RevertApplying {
		return action.BatchResult{}, fmt.Errorf("revert %s is %s, not applying", id, r.rec.Status)
	}
	r.rec.Batches++
	res := action.BatchResult{RevertID: id, Batch: r.rec.Batches}
	for _, no := range nos {
		if no < 1 || no > len(r.lines) {
			return action.BatchResult{}, fmt.Errorf("revert %s has no line %d", id, no)
		}
		l := &r.lines[no-1]
		if l.outcome == guardmodel.OutcomePending {
			s.applyLine(l, r.rec.Batches)
		}
		res.Items = append(res.Items, action.BatchItem{Line: no, Outcome: l.outcome, Conflict: l.conflict, StoreCode: l.code})
	}
	r.progress()
	if r.rec.Progress.Pending == 0 {
		r.rec.Status = action.RevertApplied
	}
	res.Status, res.Restored, res.Skipped, res.Pending = r.rec.Status, r.rec.Progress.Restored, r.rec.Progress.Skipped, r.rec.Progress.Pending
	return res, nil
}

// Proofs.

func (s *memStore) ApplyRevert(_ context.Context, id uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("ApplyRevert")
	r, ok := s.reverts[id]
	switch {
	case !ok:
		return action.AppliedRevert{}, s.refuseRevert(action.RevertSignature, "no such revert", "")
	case r.rec.Status != action.RevertPending:
		return action.AppliedRevert{}, s.refuseRevert(action.RevertAlreadySigned, "the revert is "+r.rec.Status, "")
	case !slices.Equal(a.Signature, personAssertion(r.rec.BindingText).Signature):
		return action.AppliedRevert{}, s.refuseRevert(action.RevertSignature, "the passkey's signature does not match the binding", "")
	}
	if !r.rec.Batched {
		var changed []string
		for _, l := range r.lines {
			if l.restore && s.docs[l.resource][l.key].version != l.version {
				changed = append(changed, l.resource+" "+l.key)
			}
		}
		if changed != nil {
			return action.AppliedRevert{}, s.refuseRevert(action.RevertRowsChanged,
				"documents changed since the preview: "+strings.Join(changed, ", ")+"; nothing was reverted", "")
		}
	}
	signed, ch := time.Now().UTC(), s.nextID()
	r.rec.SignedAt, r.rec.ChangeID = &signed, &ch
	if r.rec.Batched {
		applyBy := signed.Add(revert.ApplyWindow)
		r.rec.Status, r.rec.ApplyBy = action.RevertApplying, &applyBy
		r.progress()
		return action.AppliedRevert{ChangeID: ch, Batched: true, Pending: r.rec.Progress.Pending, ApplyBy: &applyBy}, nil
	}
	for i := range r.lines {
		s.applyLine(&r.lines[i], 0)
	}
	r.rec.Status = action.RevertApplied
	return action.AppliedRevert{ChangeID: ch, Rows: r.rec.Rows, Skipped: r.rec.Skipped}, nil
}

func (s *memStore) RescopeRevert(context.Context, action.RescopeRequest, time.Duration) (action.RescopedRevert, error) {
	return action.RescopedRevert{}, errUnsupported
}

func (s *memStore) RejectRevert(context.Context, uuid.UUID, string, []byte) (action.RejectedRevert, error) {
	return action.RejectedRevert{}, errUnsupported
}

func (s *memStore) RevealRevertRows(context.Context, uuid.UUID, passkey.Assertion, []byte) (action.RevealedRevert, error) {
	return action.RevealedRevert{}, errUnsupported
}
