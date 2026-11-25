package revert_test

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/channel/channeltest"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule/textruletest"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/revert/in/revertmcp"
)

// This file drives the revert service through its ports only, over a
// versioned object store that is not SQL: resources are collections named
// "namespace/collection", objects are keyed by id and carry a version, a
// revert line puts an object's earlier version back, and the store's error
// codes are its own words, not SQLSTATEs. The agent reaches the service
// through the MCP tools, the person through the page's calls. If the service
// parsed a resource name, read a store code as a SQLSTATE or decided on the
// store's error text, these tests would fail.

// objVerbs are the object store's own words for a line's operation.
var objVerbs = map[string]string{approval.OpInsert: "putObject", approval.OpUpdate: "putObject", approval.OpDelete: "deleteObject"}

const (
	objAgent = "docbot"
	// objStoreKind is the store's kind, a label only.
	objStoreKind = "OBJSTORE"
	// objPrepareLimit is the store's own time limit on a prepare.
	objPrepareLimit = 42 * time.Second
	// codeKeyExists and codeDeadline are the store's own error codes.
	codeKeyExists = "E_KEY_EXISTS"
	codeDeadline  = "DEADLINE_EXCEEDED"
)

var objNow = time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)

// The runs the tests revert: the agent's small run over photos and albums,
// its bulk run over customers and orders, a run the store stops at its time
// limit, and another agent's run.
var (
	runPhotos = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a1")
	runBulk   = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a2")
	runSlow   = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a3")
	runOther  = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a4")
)

// bulkCustomers is how many customers the bulk run changed: with its two
// orders, a plan of more than revert.MaxLines lines.
const bulkCustomers = 1100

// objResourceName is the store's form of a resource name.
var objResourceName = regexp.MustCompile(`^[a-z]+/[a-z]+$`)

// objFilterNameDetail is the store's text for a resource name it cannot use.
const objFilterNameDetail = "resources are namespace/collection names, like media/photos"

// object is one stored object: its fields (nil once deleted) and its
// version, which every write moves on.
type object struct {
	doc     map[string]any
	version int
}

// objChange is one recorded change: who made it, in which run, and the
// object before and after (nil: it did not exist).
type objChange struct {
	id, run       uuid.UUID
	agent         string
	resource, key string
	before, after map[string]any
	// version is the object's version this change made.
	version int
}

// objLine is one line of a revert: its signed text, and what the store
// needs to apply it.
type objLine struct {
	no            int
	text          string
	resource, key string
	op            string
	// set is what the revert puts back (nil deletes the object); version is
	// the object's version the line was prepared over.
	set     map[string]any
	version int
	restore bool
	outcome string
	// conflict and code say why a line was skipped, code in the store's own
	// words.
	conflict, code string
	batch          *int
}

type objRevert struct {
	rec   action.Revert
	lines []objLine
}

// objectStore is a versioned object store implementing the revert's
// Records, Undo and Proofs in memory. It checks the person's assertion
// itself (InStoreSignatureCheck), and keeps every object's history
// (RetainsHistory); a preview is computed, not a trial run.
type objectStore struct {
	mu      sync.Mutex
	objects map[string]map[string]*object
	changes []objChange
	reverts map[uuid.UUID]*objRevert
	ids     int
	// prepareLimits are the time limits the service gave each prepare.
	prepareLimits []time.Duration
	// calls counts the store's revert calls by name.
	calls map[string]int
	// asPostgres makes every refusal the one the Postgres adapter maps the
	// guard's answer to: same reason, the guard's text and SQLSTATE.
	asPostgres bool
}

func newObjectStore() *objectStore {
	return &objectStore{objects: map[string]map[string]*object{}, reverts: map[uuid.UUID]*objRevert{}, calls: map[string]int{}}
}

// nextID is a fixed sequence of ids, the same in every store.
func (s *objectStore) nextID() uuid.UUID {
	s.ids++
	return uuid.MustParse(fmt.Sprintf("0193a4c2-7d1e-7c3a-9f00-%012d", 1000+s.ids))
}

// write sets an object (nil deletes it) and moves its version on.
func (s *objectStore) write(resource, key string, doc map[string]any) (before map[string]any, version int) {
	if s.objects[resource] == nil {
		s.objects[resource] = map[string]*object{}
	}
	o := s.objects[resource][key]
	if o == nil {
		o = &object{}
		s.objects[resource][key] = o
	}
	before = o.doc
	o.doc, o.version = maps.Clone(doc), o.version+1
	return before, o.version
}

// agentWrite is a change by agent in run, recorded.
func (s *objectStore) agentWrite(agent string, run uuid.UUID, resource, key string, doc map[string]any) {
	before, version := s.write(resource, key, doc)
	s.changes = append(s.changes, objChange{
		id: s.nextID(), run: run, agent: agent, resource: resource, key: key, before: before, after: maps.Clone(doc), version: version,
	})
}

// personWrite is a change by a person, which a revert never overwrites.
func (s *objectStore) personWrite(resource, key string, doc map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write(resource, key, doc)
}

func (s *objectStore) doc(resource, key string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.objects[resource][key]; o != nil {
		return o.doc
	}
	return nil
}

// postgresRefusals are the refusals the Postgres adapter maps the guard's
// answers to, as its own table test has them: the reason, the guard's text
// and the SQLSTATE.
var postgresRefusals = []postgresRefusal{
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
	i := slices.IndexFunc(postgresRefusals, func(p postgresRefusal) bool { return p.reason == reason })
	if i < 0 {
		panic("no Postgres refusal for " + reason)
	}
	return postgresRefusals[i]
}

// refuse is the store's refusal of a call for reason, with its own text
// and code.
func (s *objectStore) refuse(reason action.RevertReason, detail, code string) error {
	if s.asPostgres {
		pg := postgresRefusalOf(reason)
		detail, code = pg.detail, pg.code
	}
	return &action.RevertRefusalError{
		Reason: reason, Detail: detail, StoreCode: code,
		Err: fmt.Errorf("store refused the revert call: %s", cmp.Or(detail, code, string(reason))),
	}
}

// selectChanges are the agent's changes in scope, narrowed to its
// resources. The store checks the names: their form, and that the agent
// wrote each one in the scope.
func (s *objectStore) selectChanges(scope action.Scope) ([]objChange, error) {
	for _, name := range scope.Tables {
		if !objResourceName.MatchString(name) {
			return nil, s.refuse(action.RevertFilterName, objFilterNameDetail, "")
		}
	}
	var own []objChange
	for _, c := range s.changes {
		in := (scope.Kind == revert.ScopeRun && c.run == scope.ID) || (scope.Kind == revert.ScopeChange && c.id == scope.ID)
		if in && c.agent == objAgent {
			own = append(own, c)
		}
	}
	if len(own) == 0 {
		switch scope.Kind {
		case revert.ScopeRun:
			return nil, s.refuse(action.RevertNotOwnRun, fmt.Sprintf("run %s has no change of %s", scope.ID, objAgent), "")
		case revert.ScopeChange:
			return nil, s.refuse(action.RevertNotOwnChange, fmt.Sprintf("change %s is not %s's", scope.ID, objAgent), "")
		case revert.ScopeTask:
		}
		return nil, s.refuse(action.RevertInvalid, "this store reverts a change or a run", "")
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
			return nil, s.refuse(action.RevertFilter, name+" has no change of yours in this run", "")
		}
	}
	return slices.DeleteFunc(own, func(c objChange) bool { return !slices.Contains(scope.Tables, c.resource) }), nil
}

func rawJSON(v map[string]any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// planLines are the lines that put back what changes changed, one per
// object, in resource and key order: the object as it was before the
// agent's first change, unless someone changed it after the agent's last.
func (s *objectStore) planLines(changes []objChange) []objLine {
	type target struct{ resource, key string }
	first, last, ids := map[target]objChange{}, map[target]objChange{}, map[target][]uuid.UUID{}
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
	out := make([]objLine, 0, len(order))
	for _, t := range order {
		f, l, cur := first[t], last[t], s.objects[t.resource][t.key]
		line := revert.Line{
			Op: approval.OpUpdate, Key: rawJSON(map[string]any{"_id": t.key}), Now: rawJSON(cur.doc), Set: rawJSON(f.before),
			Shape: approval.ShapeRecord, Resource: t.resource, Action: revert.ActionRestore, ChangeIDs: ids[t],
		}
		switch {
		case f.before == nil:
			line.Op = approval.OpDelete
		case l.after == nil:
			line.Op = approval.OpInsert
		}
		line.Store = revert.LineStore{Kind: objStoreKind, Verb: objVerbs[line.Op]}
		ol := objLine{resource: t.resource, key: t.key, op: line.Op, set: f.before, version: l.version, restore: true}
		switch {
		case cur.version != l.version && line.Op == approval.OpInsert && cur.doc != nil:
			ol.conflict, ol.code = revert.ConflictKeyTaken, codeKeyExists
		case cur.version != l.version:
			ol.conflict = revert.ConflictChangedAfter
		}
		if ol.conflict != "" {
			ol.restore, line.Action, line.Conflict = false, revert.ActionSkip, &ol.conflict
			if ol.code != "" {
				line.Store.Code = &ol.code
			}
		}
		ol.text = textruletest.MustText(line)
		out = append(out, ol)
	}
	return out
}

func lineHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func (s *objectStore) count(name string) {
	s.calls[name]++
}

// Records.

func (s *objectStore) FindRevert(_ context.Context, id uuid.UUID) (action.Revert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("FindRevert")
	r, ok := s.reverts[id]
	if !ok {
		return action.Revert{}, s.refuse(action.RevertNotFound, "", "")
	}
	out := r.rec
	out.Lines = slices.Clone(r.rec.Lines)
	return out, nil
}

func (s *objectStore) RevertLines(_ context.Context, p action.RevertLineParams) (pagination.Page[action.RevertLine], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("RevertLines")
	r, ok := s.reverts[p.RevertID]
	if !ok {
		return pagination.Page[action.RevertLine]{}, s.refuse(action.RevertNotFound, "", "")
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

func (s *objectStore) ListOpenReverts(context.Context, action.RevertListParams) (pagination.Page[action.Revert], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out pagination.Page[action.Revert]
	for _, r := range s.reverts {
		if r.rec.Status == action.RevertPending || r.rec.Status == action.RevertApplying {
			out.Items = append(out.Items, r.rec)
		}
	}
	return out, nil
}

func (s *objectStore) RevertedBy(context.Context, action.Scope) (uuid.UUID, error) {
	return uuid.Nil, nil
}

func (s *objectStore) HasChange(_ context.Context, id uuid.UUID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.ContainsFunc(s.changes, func(c objChange) bool { return c.id == id && c.agent == objAgent }), nil
}

func (s *objectStore) HasTaskRun(context.Context, uuid.UUID) (bool, error) { return false, nil }

func (s *objectStore) RevertNonce(_ context.Context, id uuid.UUID) ([]byte, error) {
	sum := sha256.Sum256([]byte("rescope " + id.String()))
	return sum[:], nil
}

func (s *objectStore) RevealNonce(_ context.Context, _ string, id uuid.UUID) ([]byte, error) {
	sum := sha256.Sum256([]byte("reveal " + id.String()))
	return sum[:], nil
}

// Undo.

func (s *objectStore) PreviewRevert(_ context.Context, scope action.Scope, after string, limit int) (action.PreviewPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("PreviewRevert")
	if scope.ID == runSlow {
		return action.PreviewPage{}, s.refuse(action.RevertTimedOut, "", codeDeadline)
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

func (s *objectStore) PrepareRevert(_ context.Context, scope action.Scope, intent string, timeout time.Duration) (action.PreparedRevert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("PrepareRevert")
	s.prepareLimits = append(s.prepareLimits, timeout)
	if scope.ID == runSlow {
		return action.PreparedRevert{}, s.refuse(action.RevertTimedOut, "", codeDeadline)
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
		return action.PreparedRevert{}, s.refuse(action.RevertNothing, "every object changed after the agent", "")
	}
	id := s.nextID()
	b := revert.Binding{
		Kind: revert.KindRevert, RevertID: id, Store: approval.BindingStore{Kind: objStoreKind, Name: "media-archive"},
		Select: revert.Select{Scope: scope.Kind, ScopeID: scope.ID, Agents: []string{approval.AgentName(objAgent)}, Runs: scope.Runs, Resources: scope.Tables},
		Intent: intent, Rows: restore, Skipped: len(lines) - restore, RowsHash: approval.RowsHash(texts),
		ExpiresAt: objNow.Add(time.Hour), RequestedBy: approval.AgentName(objAgent),
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
	s.reverts[id] = &objRevert{lines: lines, rec: action.Revert{
		ID: id, Status: action.RevertPending, Scope: string(scope.Kind), ScopeID: scope.ID, Intent: intent,
		Rows: b.Rows, Skipped: b.Skipped, ExpiresAt: b.ExpiresAt, BindingText: binding, Lines: shown,
		Batched: b.Batched, CreatedAt: objNow,
	}}
	return action.PreparedRevert{RevertID: id, BindingText: binding, ExpiresAt: b.ExpiresAt, Batched: b.Batched, LineCount: len(lines)}, nil
}

var errObjUnsupported = errors.New("the object store under test does not reset, rescope, reject or reveal a revert")

func (s *objectStore) ResetRevert(context.Context, uuid.UUID, time.Duration) (action.RescopedRevert, error) {
	return action.RescopedRevert{}, errObjUnsupported
}

// applyLine applies one line: the object goes back to its earlier version,
// unless someone changed it since the line was prepared (people win).
func (s *objectStore) applyLine(l *objLine, batch int) {
	if batch > 0 {
		l.batch = &batch
	}
	if !l.restore {
		l.outcome = guardmodel.OutcomeSkipped
		return
	}
	cur := s.objects[l.resource][l.key]
	switch {
	case cur.version != l.version && l.op == approval.OpInsert && cur.doc != nil:
		l.outcome, l.conflict, l.code = guardmodel.OutcomeSkipped, revert.ConflictKeyTaken, codeKeyExists
	case cur.version != l.version:
		l.outcome, l.conflict = guardmodel.OutcomeSkipped, revert.ConflictChangedAfter
	default:
		s.write(l.resource, l.key, l.set)
		l.outcome = guardmodel.OutcomeRestored
	}
}

func (r *objRevert) progress() {
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

func (s *objectStore) ApplyRevertBatch(_ context.Context, id uuid.UUID, nos []int) (action.BatchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("ApplyRevertBatch")
	r, ok := s.reverts[id]
	if !ok {
		return action.BatchResult{}, s.refuse(action.RevertNotFound, "", "")
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

// personAssertion is the person's passkey assertion over a binding: the
// test's stand-in for a signature, which the store checks itself.
func personAssertion(binding string) passkey.Assertion {
	sum := sha256.Sum256([]byte("the person's passkey signs " + binding))
	return passkey.Assertion{
		CredentialID: passkey.Bytes("person-passkey"), AuthenticatorData: passkey.Bytes("authenticator"),
		ClientDataJSON: passkey.Bytes(`{"type":"webauthn.get"}`), Signature: sum[:],
	}
}

func (s *objectStore) ApplyRevert(_ context.Context, id uuid.UUID, a passkey.Assertion) (action.AppliedRevert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count("ApplyRevert")
	r, ok := s.reverts[id]
	switch {
	case !ok:
		return action.AppliedRevert{}, s.refuse(action.RevertSignature, "no such revert", "")
	case r.rec.Status != action.RevertPending:
		return action.AppliedRevert{}, s.refuse(action.RevertAlreadySigned, "the revert is "+r.rec.Status, "")
	case !slices.Equal(a.Signature, personAssertion(r.rec.BindingText).Signature):
		return action.AppliedRevert{}, s.refuse(action.RevertSignature, "the passkey's signature does not match the binding", "")
	}
	if !r.rec.Batched {
		var changed []string
		for _, l := range r.lines {
			if l.restore && s.objects[l.resource][l.key].version != l.version {
				changed = append(changed, l.resource+" "+l.key)
			}
		}
		if changed != nil {
			return action.AppliedRevert{}, s.refuse(action.RevertRowsChanged,
				"objects changed since the preview: "+strings.Join(changed, ", ")+"; nothing was reverted", "")
		}
	}
	signed, change := objNow, s.nextID()
	r.rec.SignedAt, r.rec.ChangeID = &signed, &change
	if r.rec.Batched {
		applyBy := objNow.Add(revert.ApplyWindow)
		r.rec.Status, r.rec.ApplyBy = action.RevertApplying, &applyBy
		r.progress()
		return action.AppliedRevert{ChangeID: change, Batched: true, Pending: r.rec.Progress.Pending, ApplyBy: &applyBy}, nil
	}
	for i := range r.lines {
		s.applyLine(&r.lines[i], 0)
	}
	r.rec.Status = action.RevertApplied
	return action.AppliedRevert{ChangeID: change, Rows: r.rec.Rows, Skipped: r.rec.Skipped}, nil
}

func (s *objectStore) RescopeRevert(context.Context, action.RescopeRequest, time.Duration) (action.RescopedRevert, error) {
	return action.RescopedRevert{}, errObjUnsupported
}

func (s *objectStore) RejectRevert(context.Context, uuid.UUID, string, []byte) (action.RejectedRevert, error) {
	return action.RejectedRevert{}, errObjUnsupported
}

func (s *objectStore) RevealRevertRows(context.Context, uuid.UUID, passkey.Assertion, []byte) (action.RevealedRevert, error) {
	return action.RevealedRevert{}, errObjUnsupported
}

// seedObjects is the agent's work the tests revert, and what people did
// after it.
func seedObjects(s *objectStore) {
	for _, key := range []string{"p1", "p2", "p3", "p9"} {
		s.write("media/photos", key, map[string]any{"_id": key, "caption": "original " + key})
	}
	s.write("media/albums", "a1", map[string]any{"_id": "a1", "title": "Summer"})
	// The small run: two captions, a deleted photo and an album title.
	s.agentWrite(objAgent, runPhotos, "media/photos", "p1", map[string]any{"_id": "p1", "caption": "wrong"})
	s.agentWrite(objAgent, runPhotos, "media/photos", "p2", map[string]any{"_id": "p2", "caption": "wrong"})
	s.agentWrite(objAgent, runPhotos, "media/photos", "p3", nil)
	s.agentWrite(objAgent, runPhotos, "media/albums", "a1", map[string]any{"_id": "a1", "title": "wrong"})
	// A person put a new photo p3 in since: its key is taken.
	s.write("media/photos", "p3", map[string]any{"_id": "p3", "caption": "a new photo"})

	for i := range bulkCustomers {
		key := fmt.Sprintf("c%04d", i)
		s.write("shop/customers", key, map[string]any{"_id": key, "plan": "trial"})
		s.agentWrite(objAgent, runBulk, "shop/customers", key, map[string]any{"_id": key, "plan": "pro"})
	}
	for _, key := range []string{"o1", "o2"} {
		s.write("shop/orders", key, map[string]any{"_id": key, "total": 10})
		s.agentWrite(objAgent, runBulk, "shop/orders", key, nil)
	}
	// A person changed one customer after the agent.
	s.write("shop/customers", "c0007", map[string]any{"_id": "c0007", "plan": "enterprise"})

	s.write("media/albums", "a2", map[string]any{"_id": "a2", "title": "Winter"})
	s.agentWrite(objAgent, runSlow, "media/albums", "a2", map[string]any{"_id": "a2", "title": "slow"})
	s.agentWrite("otherbot", runOther, "media/photos", "p9", map[string]any{"_id": "p9", "caption": "theirs"})
}

// objRuns finds every run in the ledger, the agent's or not: the store
// decides whose work a run is.
type objRuns struct{ store *objectStore }

func (r objRuns) FindRun(_ context.Context, id uuid.UUID) (action.Run, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	if slices.ContainsFunc(r.store.changes, func(c objChange) bool { return c.run == id }) {
		return action.Run{}, nil
	}
	return action.Run{}, action.ErrRunNotFound
}

// noApprovals are the approval reads the delivery use case makes: no
// passkey listed, no held write, no column order.
type noApprovals struct{}

func (noApprovals) Passkeys(context.Context) ([]passkey.Credential, error) { return nil, nil }
func (noApprovals) FindApproval(context.Context, uuid.UUID) (action.Approval, error) {
	return action.Approval{}, errors.New("no held write")
}
func (noApprovals) HasColumns() bool { return false }
func (noApprovals) ColumnOrder(context.Context, []string) (map[string][]string, error) {
	return map[string][]string{}, nil
}

type objDescribe struct{}

func (objDescribe) StatementTimeout() time.Duration { return 5 * time.Second }

type objAdmit struct{}

func (objAdmit) Admit(context.Context) error { return nil }

// The wiring's error sentinels for this store.
var (
	errObjParams       = errors.New("object store: invalid parameters")
	errObjIntent       = errors.New("object store: invalid intent")
	errObjNotConnected = errors.New("no Vault connected")
)

// objHarness is the revert service over the object store, built with its
// ports only, with the revert tools an agent calls.
type objHarness struct {
	t      *testing.T
	svc    *revertsvc.Service
	store  *objectStore
	tools  map[string]func(context.Context, json.RawMessage) (any, error)
	errors guidance.ErrorMap
	keys   *channel.EngineKeys
}

func newObjHarness(t *testing.T, asPostgres bool) *objHarness {
	t.Helper()
	store := newObjectStore()
	seedObjects(store)
	store.asPostgres = asPostgres
	keys, err := channel.GenerateEngineKeys(func() time.Time { return objNow })
	require.NoError(t, err)
	now := func() time.Time { return objNow }
	log := slog.New(slog.DiscardHandler)
	errs := guidance.ErrorMap{
		InvalidParams: errObjParams, InvalidIntent: errObjIntent,
		RowTooLarge: func(error) (string, bool) { return "", false },
	}
	cmds := guidance.NewCommands(objAgent, "", "/etc/basalt/config.toml", "linux", guidance.ServiceManager{
		StartCommand: func(string) string { return "basalt start" }, RestartArgs: func(string) []string { return []string{"restart"} },
	})
	delivery := linksvc.New(
		linksvc.Core{Name: objAgent, Log: log, Now: now, Commands: cmds, Errors: errs, PagesBase: links.DefaultLocal, PagesOrigin: links.DefaultLocal},
		&linksvc.Deps{
			Notifier: linksvc.NoNotifier{}, Links: links.NewSecrets(now, rand.Reader), Poll: time.Millisecond,
			Relay: linksvc.NoRelay{NotConnected: errObjNotConnected}, VaultConflict: func(error) bool { return false },
			ErrVaultNotConnected: errObjNotConnected, Receipts: keys,
		},
		noApprovals{},
		func(_ string, _ map[string]any, err error) *toolresult.ToolError { return errs.ToolError(err) },
	)
	svc := revertsvc.New(
		revertsvc.Core{
			Name: objAgent, Log: log, Now: now, Commands: cmds, Errors: errs,
			PagesBase: links.DefaultLocal, LinkBudget: links.DefaultBudget,
		},
		revertsvc.StoreSet{
			Limits:  revertsvc.Limits{Prepare: objPrepareLimit},
			Records: store, Undo: store, Proofs: store,
		},
		&revertsvc.Deps{
			AfterAnswer:   func(context.Context, func()) bool { return false },
			RotateSession: func(context.Context, channel.LinkToken) bool { return false },
		},
		objRuns{store}, delivery, objDescribe{}, objAdmit{},
	)
	h := &objHarness{t: t, svc: svc, store: store, tools: map[string]func(context.Context, json.RawMessage) (any, error){}, errors: errs, keys: keys}
	revertmcp.Tools(svc, func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool {
		h.tools[name] = call
		return mcpserver.Tool{}
	})
	return h
}

// call is the agent's tool call: its answer as the agent reads it, or the
// error the wiring maps it to.
func (h *objHarness) call(name string, args map[string]any) (map[string]any, *toolresult.ToolError) {
	h.t.Helper()
	raw, err := json.Marshal(args)
	require.NoError(h.t, err)
	tool, ok := h.tools[name]
	require.True(h.t, ok, name)
	out, err := tool(context.Background(), raw)
	if err != nil {
		return nil, h.errors.ToolError(err)
	}
	b, err := json.Marshal(out)
	require.NoError(h.t, err)
	var m map[string]any
	require.NoError(h.t, json.Unmarshal(b, &m))
	return m, nil
}

// mustCall is a tool call that must succeed.
func (h *objHarness) mustCall(name string, args map[string]any) map[string]any {
	h.t.Helper()
	out, te := h.call(name, args)
	require.Nil(h.t, te, "%s answered %+v", name, te)
	return out
}

// personSigns is the person on the revert page the agent's link opens:
// the page reads the request, checks it against the binding, and posts
// the signed response.
func (h *objHarness) personSigns(revertURL string) (revert.Request, revert.Binding, action.AppliedRevert, linksvc.Receipt, error) {
	h.t.Helper()
	u, err := url.Parse(revertURL)
	require.NoError(h.t, err)
	id, err := uuid.Parse(path.Base(u.Path))
	require.NoError(h.t, err)
	secret, ok := strings.CutPrefix(u.Fragment, "s=")
	require.True(h.t, ok, "a short link carries its secret: %s", revertURL)
	req, err := h.svc.RevertRequest(context.Background(), id, secret)
	require.NoError(h.t, err)
	b, err := req.Check()
	require.NoError(h.t, err, "the page checks the request before asking for a signature")
	applied, receipt, err := h.svc.RelayRevert(context.Background(), reverttest.NewResponse(id, personAssertion(req.Binding)))
	return req, b, applied, receipt, err
}

// items are the answer's items as the agent reads them.
func items(t *testing.T, answer map[string]any) []map[string]any {
	t.Helper()
	raw, ok := answer["items"].([]any)
	require.True(t, ok, "answer has items: %v", answer)
	out := make([]map[string]any, 0, len(raw))
	for _, it := range raw {
		out = append(out, it.(map[string]any))
	}
	return out
}

// callStep is the answer's CALL_TOOL step, nil when it has none.
func callStep(answer map[string]any) map[string]any {
	steps, _ := answer["nextSteps"].([]any)
	for _, s := range steps {
		if step := s.(map[string]any); step["action"] == toolresult.ActionCallTool {
			return step
		}
	}
	return nil
}

func TestObjectStoreRevertsARunThroughThePorts(t *testing.T) {
	t.Parallel()
	h := newObjHarness(t, false)
	scope := map[string]any{"runId": runPhotos.String(), "resources": []string{"media/photos"}}

	// preview_revert: the store's resource names and code, as they are.
	preview := h.mustCall("preview_revert", scope)
	require.EqualValues(t, 2, preview["rows"])
	require.EqualValues(t, 1, preview["skipped"])
	got := items(t, preview)
	require.Len(t, got, 3)
	for _, it := range got {
		require.Equal(t, "media/photos", it["resource"])
		require.NotContains(t, it, "table")
		require.NotContains(t, it, "sqlState")
	}
	require.Equal(t, "SKIP", got[2]["action"])
	require.Equal(t, revert.ConflictKeyTaken, got[2]["conflict"])
	require.Equal(t, codeKeyExists, got[2]["storeCode"], "the store's own code, not a SQLSTATE")
	steps := preview["nextSteps"].([]any)
	require.Len(t, steps, 2)
	request := steps[1].(map[string]any)
	require.Equal(t, guidance.ToolRequestRevert, request["tool"])
	require.Equal(t, map[string]any{"runId": runPhotos.String(), "resources": []any{"media/photos"}}, request["arguments"],
		"the request keeps the resources as the agent named them")

	// request_revert: the revert is stored for the person, with the
	// store's time limit, and a short link to the page.
	requested := h.mustCall("request_revert", map[string]any{
		"runId": runPhotos.String(), "resources": []string{"media/photos"}, "intent": "the captions were wrong",
	})
	require.Equal(t, action.RevertPending, requested["status"])
	require.Equal(t, false, requested["batched"])
	require.Equal(t, []time.Duration{objPrepareLimit}, h.store.prepareLimits, "the store gets its own time limit")
	revertURL, _ := requested["revertUrl"].(string)
	require.True(t, strings.HasPrefix(revertURL, links.DefaultLocal+"/reverts/"), revertURL)

	// The person's page: real binding text, lines that hash to rowsHash.
	req, b, applied, receipt, err := h.personSigns(revertURL)
	require.NoError(t, err)
	require.Equal(t, approval.RowsHash(req.Lines), b.RowsHash)
	require.Equal(t, []string{"media/photos"}, b.Select.Resources, "the binding signs the resources as the agent named them")
	require.Equal(t, 2, b.Rows)
	require.Equal(t, 1, b.Skipped)
	for _, text := range req.Lines {
		l, err := revert.ParseLine(text)
		require.NoError(t, err)
		require.Equal(t, "media/photos", l.Resource)
	}
	require.Equal(t, 2, applied.Rows)
	p, err := channeltest.VerifyReceipt(receipt.Token, h.keys.PublicKeySPKI())
	require.NoError(t, err)
	require.Equal(t, b.RowsHash, p.RowsHash)

	// request_revert's wait form reads the store's outcome.
	done := h.mustCall("request_revert", map[string]any{"revertId": requested["revertId"], "waitForSignature": 0})
	require.Equal(t, action.RevertApplied, done["status"])
	require.Equal(t, applied.ChangeID.String(), done["changeId"])

	require.Equal(t, "original p1", h.store.doc("media/photos", "p1")["caption"])
	require.Equal(t, "original p2", h.store.doc("media/photos", "p2")["caption"])
	require.Equal(t, "a new photo", h.store.doc("media/photos", "p3")["caption"], "people win")
	require.Equal(t, "wrong", h.store.doc("media/albums", "a1")["title"], "outside the agent's resources filter")
}

func TestObjectStoreAppliesABatchedPlanThroughThePorts(t *testing.T) {
	t.Parallel()
	h := newObjHarness(t, false)
	lines := bulkCustomers + 2

	requested := h.mustCall("request_revert", map[string]any{"runId": runBulk.String(), "intent": "the plan upgrade was a mistake"})
	require.Equal(t, true, requested["batched"])
	require.EqualValues(t, lines-1, requested["rows"])
	require.EqualValues(t, 1, requested["skipped"])

	// The page gets the plan's sample and checks it against sampleHash.
	req, b, applied, _, err := h.personSigns(requested["revertUrl"].(string))
	require.NoError(t, err)
	require.True(t, b.Batched)
	require.Len(t, req.Lines, revert.MaxLines)
	require.Equal(t, approval.RowsHash(req.Lines), b.SampleHash)
	require.True(t, applied.Batched)
	require.Equal(t, lines, applied.Pending)

	// After the signature, a person changed a customer and put a new order
	// o2 in: those lines are skipped as the batches reach them.
	h.store.personWrite("shop/customers", "c0500", map[string]any{"_id": "c0500", "plan": "team"})
	h.store.personWrite("shop/orders", "o2", map[string]any{"_id": "o2", "total": 99})

	// The agent follows the engine's steps: revert_plan for the pending
	// lines, apply_revert_batch with them, until the plan is done.
	answer := h.mustCall("request_revert", map[string]any{"revertId": requested["revertId"], "waitForSignature": 0})
	require.Equal(t, action.RevertApplying, answer["status"])
	var batched []map[string]any
	plans := 0
	for step := callStep(answer); step != nil; step = callStep(answer) {
		require.Less(t, plans, 20, "the plan ends")
		answer = h.mustCall(step["tool"].(string), step["arguments"].(map[string]any))
		switch step["tool"] {
		case guidance.ToolRevertPlan:
			plans++
			for _, it := range items(t, answer) {
				plan := it["plan"].(map[string]any)
				require.Contains(t, []string{"shop/customers", "shop/orders"}, plan["resource"])
				require.NotContains(t, plan, "table")
			}
		case guidance.ToolApplyRevertBatch:
			batched = append(batched, items(t, answer)...)
		}
	}
	require.Equal(t, action.RevertApplied, answer["status"])
	require.Len(t, batched, lines)
	require.Equal(t, 6, plans, "200 lines a batch")
	require.Equal(t, 6, h.store.calls["ApplyRevertBatch"])
	require.EqualValues(t, lines-3, answer["restored"])
	require.EqualValues(t, 3, answer["skipped"])
	require.EqualValues(t, 0, answer["pending"])

	last := batched[len(batched)-1]
	require.EqualValues(t, lines, last["line"])
	require.Equal(t, guardmodel.OutcomeSkipped, last["outcome"])
	require.Equal(t, revert.ConflictKeyTaken, last["conflict"])
	require.Equal(t, codeKeyExists, last["storeCode"], "the store's own code, not a SQLSTATE")
	require.NotContains(t, last, "sqlState")

	require.Equal(t, "trial", h.store.doc("shop/customers", "c0000")["plan"])
	require.Equal(t, "team", h.store.doc("shop/customers", "c0500")["plan"], "people win")
	require.Equal(t, "enterprise", h.store.doc("shop/customers", "c0007")["plan"], "people win")
	require.EqualValues(t, 10, h.store.doc("shop/orders", "o1")["total"])
	require.EqualValues(t, 99, h.store.doc("shop/orders", "o2")["total"], "people win")
}

// refusalCase is one refusal of the store: how the agent or the person runs
// into it, and the store's own text and code for it.
type refusalCase struct {
	name   string
	reason action.RevertReason
	// detail and code are the object store's; the Postgres adapter's are in
	// postgresRefusals. shown: the answer's message shows the detail.
	detail, code string
	shown        bool
	run          func(h *objHarness) *toolresult.ToolError
}

func refusalCases() []refusalCase {
	request := func(args map[string]any) func(h *objHarness) *toolresult.ToolError {
		return func(h *objHarness) *toolresult.ToolError {
			args["intent"] = "undo it"
			_, te := h.call("request_revert", args)
			return te
		}
	}
	preview := func(args map[string]any) func(h *objHarness) *toolresult.ToolError {
		return func(h *objHarness) *toolresult.ToolError {
			_, te := h.call("preview_revert", args)
			return te
		}
	}
	missing := uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000ff").String()
	return []refusalCase{
		{
			name: "request_revert: a resource name the store cannot use", reason: action.RevertFilterName, detail: objFilterNameDetail, shown: true,
			run: request(map[string]any{"runId": runPhotos.String(), "resources": []string{"public.photos"}}),
		},
		{
			name: "preview_revert: a resource name the store cannot use", reason: action.RevertFilterName, detail: objFilterNameDetail, shown: true,
			run: preview(map[string]any{"runId": runPhotos.String(), "resources": []string{"photos"}}),
		},
		{
			name: "request_revert: a resource the agent did not write", reason: action.RevertFilter, shown: true,
			detail: "media/videos has no change of yours in this run",
			run:    request(map[string]any{"runId": runPhotos.String(), "resources": []string{"media/videos"}}),
		},
		{
			name: "request_revert: another agent's run", reason: action.RevertNotOwnRun,
			detail: fmt.Sprintf("run %s has no change of %s", runOther, objAgent),
			run:    request(map[string]any{"runId": runOther.String()}),
		},
		{
			name: "request_revert: the store's time limit", reason: action.RevertTimedOut, code: codeDeadline,
			run: request(map[string]any{"runId": runSlow.String()}),
		},
		{
			name: "preview_revert: the store's time limit", reason: action.RevertTimedOut, code: codeDeadline,
			run: preview(map[string]any{"runId": runSlow.String()}),
		},
		{
			name: "revert_plan: a revert the agent did not prepare", reason: action.RevertNotFound,
			run: func(h *objHarness) *toolresult.ToolError {
				_, te := h.call("revert_plan", map[string]any{"revertId": missing})
				return te
			},
		},
		{
			name: "request_revert: wait for a revert the agent did not prepare", reason: action.RevertNotFound,
			run: func(h *objHarness) *toolresult.ToolError {
				_, te := h.call("request_revert", map[string]any{"revertId": missing, "waitForSignature": 0})
				return te
			},
		},
		{
			name: "the person's apply: an object changed since the preview", reason: action.RevertRowsChanged, shown: true,
			detail: "objects changed since the preview: media/photos p1; nothing was reverted",
			run: func(h *objHarness) *toolresult.ToolError {
				requested := h.mustCall("request_revert", map[string]any{
					"runId": runPhotos.String(), "resources": []string{"media/photos"}, "intent": "undo it",
				})
				h.store.personWrite("media/photos", "p1", map[string]any{"_id": "p1", "caption": "fixed by hand"})
				_, _, _, _, err := h.personSigns(requested["revertUrl"].(string))
				require.Error(h.t, err)
				return h.errors.ToolError(err)
			},
		},
	}
}

// Each refusal of the object store gives the agent the answer the same
// refusal of the Postgres store gives: the same code, reason, steps and
// person's message, with the store's own text where the answer shows it,
// and the store's own code.
func TestObjectStoreRefusalsGiveThePostgresAnswers(t *testing.T) {
	t.Parallel()
	for _, c := range refusalCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			obj := newObjHarness(t, false)
			got := c.run(obj)
			require.NotNil(t, got, "the store refused")
			require.NotEmpty(t, obj.store.calls, "the store was asked, not the service's own check")
			pgHarness := newObjHarness(t, true)
			want := c.run(pgHarness)
			require.NotNil(t, want)
			pg := postgresRefusalOf(c.reason)

			require.NotEqual(t, guidance.CodeInternal, got.Code, "a refusal, not an engine error: %+v", got)
			require.Equal(t, want.Code, got.Code)
			require.Equal(t, want.Reason, got.Reason)
			require.Equal(t, want.PersonMessage, got.PersonMessage)
			require.Equal(t, want.NextSteps, got.NextSteps)
			wantMessage := want.Message
			if c.shown {
				require.Contains(t, want.Message, pg.detail)
				require.Contains(t, got.Message, c.detail, "the store's own text, verbatim")
				wantMessage = strings.ReplaceAll(want.Message, pg.detail, c.detail)
			}
			require.Equal(t, wantMessage, got.Message)
			require.Equal(t, pg.code, want.SQLState)
			require.Equal(t, c.code, got.SQLState, "the store's own code, passed on as it is")
			if c.reason == action.RevertTimedOut && strings.Contains(c.name, "request_revert") {
				require.Contains(t, got.Message, strconv.Itoa(int(objPrepareLimit.Seconds()))+" seconds", "the store's own time limit")
			}
		})
	}
}

// A refusal for a resource name reaches the store: the service never checks
// a name's form itself.
func TestObjectStoreChecksTheResourceNames(t *testing.T) {
	t.Parallel()
	h := newObjHarness(t, false)
	_, te := h.call("preview_revert", map[string]any{"runId": runPhotos.String(), "resources": []string{"public.photos"}})
	require.NotNil(t, te)
	require.Equal(t, guidance.CodeInvalidArgument, te.Code)
	require.Equal(t, guidance.ReasonScopeFilter, te.Reason)
	require.Equal(t, "the revert filter is not valid, nothing was prepared: "+objFilterNameDetail, te.Message)
	require.Equal(t, 1, h.store.calls["PreviewRevert"])

	// A name of the store's form passes, though it is not schema.table.
	preview := h.mustCall("preview_revert", map[string]any{"runId": runPhotos.String(), "resources": []string{"media/albums"}})
	require.Equal(t, "media/albums", items(t, preview)[0]["resource"])
}
