//go:build linux || darwin

package person_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/peercred"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// Uids of the cases: the recorded person, the agent's OS user and a third
// local user. They stand in for other OS users, so none may be root or this
// process's own uid, which the server refuses even when recorded (a CI
// runner's user is often uid 1001).
var personUID, agentUID, otherUID = fakeUIDs()

// firstFakeUID is the first uid fakeUIDs considers.
const firstFakeUID uint32 = 1001

// fakeUIDs returns three distinct uids from firstFakeUID on, skipping this
// process's own.
func fakeUIDs() (person, agent, other uint32) {
	self := uint32(os.Getuid())
	var uids [3]uint32
	n := 0
	for uid := firstFakeUID; n < len(uids); uid++ {
		if uid != self {
			uids[n] = uid
			n++
		}
	}
	return uids[0], uids[1], uids[2]
}

// fakeLedger answers every call from its fields and counts the calls, so a
// test can tell a refused connection reached nothing.
type fakeLedger struct {
	calls    atomic.Int32
	changes  []ledger.Change
	keys     []ledger.Passkey
	approval ledger.Approval
	access   pgcatalog.Access
	err      error
}

func (f *fakeLedger) hit() error { f.calls.Add(1); return f.err }

func (f *fakeLedger) CheckHealth(context.Context, ledger.HealthOptions) (ledger.Health, error) {
	return ledger.Health{Chain: guard.ChainStatus{Intact: true}, Head: guard.ChainHead{Seq: 7, Hash: []byte{1, 2}}}, f.hit()
}

func (f *fakeLedger) ListChanges(_ context.Context, p ledger.ChangeListParams) (pagination.Page[ledger.Change], error) {
	if p.Limit != pagination.DefaultLimit {
		return pagination.Page[ledger.Change]{}, errors.New("limit not defaulted")
	}
	return pagination.Page[ledger.Change]{Items: f.changes, NextCursor: "next"}, f.hit()
}

func (f *fakeLedger) ListAccess(context.Context) (pgcatalog.Access, error) {
	return f.access, f.hit()
}

func (f *fakeLedger) RowChanges(context.Context, []uuid.UUID) (map[uuid.UUID][]ledger.RowChange, error) {
	return nil, f.hit()
}

func (f *fakeLedger) ListPasskeys(context.Context) ([]ledger.Passkey, error) { return f.keys, f.hit() }

func (f *fakeLedger) FindApproval(context.Context, uuid.UUID) (ledger.Approval, error) {
	return f.approval, f.hit()
}

func (f *fakeLedger) SubmitApproval(context.Context, uuid.UUID, passkey.Assertion) (time.Time, error) {
	return time.Time{}, f.hit()
}

func (f *fakeLedger) FindRevert(context.Context, uuid.UUID) (ledger.Revert, error) {
	return ledger.Revert{}, f.hit()
}

func (f *fakeLedger) PreviewRevert(context.Context, guard.RevertScope) ([]string, error) {
	return []string{"line"}, f.hit()
}

func (f *fakeLedger) PrepareRevert(context.Context, guard.RevertScope, string) (guard.PreparedRevert, error) {
	return guard.PreparedRevert{}, f.hit()
}

func (f *fakeLedger) ApplyRevert(context.Context, uuid.UUID, passkey.Assertion) (guard.AppliedRevert, error) {
	return guard.AppliedRevert{}, f.hit()
}

func (f *fakeLedger) RescopeRevert(context.Context, uuid.UUID, []uuid.UUID, []string) (guard.PreparedRevert, error) {
	return guard.PreparedRevert{}, f.hit()
}

func (f *fakeLedger) RejectRevert(context.Context, uuid.UUID, string) (guard.RejectedRevert, error) {
	return guard.RejectedRevert{}, f.hit()
}

func (f *fakeLedger) ListRevertLines(context.Context, ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error) {
	return pagination.Page[ledger.RevertLine]{}, f.hit()
}

// socketPath is a socket path short enough for macOS (about 104 bytes).
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bps")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "person.sock")
}

// serve runs a person server on a real Unix socket in a temp dir, with the
// peer's uid read by peer (a fixed uid stands in for another OS user, so
// the tests run without root).
func serve(t *testing.T, allow []uint32, peer person.PeerUIDFunc, l person.Ledger) person.Client {
	t.Helper()
	return serveWith(t, person.Options{Allow: allow, Agents: map[string]person.Ledger{"bot": l}, PeerUID: peer})
}

// serveWith is serve with every option given.
func serveWith(t *testing.T, o person.Options) person.Client {
	t.Helper()
	path := socketPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	o.Pages = person.PagesDTO{PagesURL: "http://localhost:8787", UpdateCheck: "OFF", LocalOrigin: "http://localhost:8787"}
	o.Log = slog.New(slog.DiscardHandler)
	srv := person.NewServer(o)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return person.Client{Path: path}
}

func peerIs(uid uint32) person.PeerUIDFunc {
	return func(*net.UnixConn) (uint32, error) { return uid, nil }
}

func TestThePersonSocketAdmitsOnlyRecordedPersons(t *testing.T) {
	t.Parallel()
	self := uint32(os.Getuid())
	cases := []struct {
		name  string
		allow []uint32
		peer  uint32
		ok    bool
	}{
		{"the recorded person", []uint32{personUID}, personUID, true},
		{"a second recorded person", []uint32{personUID, otherUID}, otherUID, true},
		{"the agent's OS user", []uint32{personUID}, agentUID, false},
		{"a third local user", []uint32{personUID}, otherUID, false},
		{"the engine's own user, even when recorded", []uint32{personUID, self}, self, false},
		{"root, even when recorded", []uint32{personUID, 0}, 0, false},
		{"an empty allowlist", nil, personUID, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := &fakeLedger{changes: []ledger.Change{{ID: uuid.Must(uuid.NewV7()), Op: "UPDATE", Rows: 3, Params: json.RawMessage(`{}`)}}}
			c := serve(t, tc.allow, peerIs(tc.peer), l)
			page, err := c.Agent("bot").ListChanges(context.Background(), ledger.ChangeListParams{})
			if tc.ok {
				require.NoError(t, err)
				require.Equal(t, l.changes, page.Items)
				require.Equal(t, "next", page.NextCursor)
				return
			}
			require.ErrorIs(t, err, person.ErrUIDNotAllowed)
			require.Zero(t, l.calls.Load(), "a refused peer reaches no ledger call")
		})
	}
}

func TestThePersonSocketChecksTheRealPeerBeforeReading(t *testing.T) {
	t.Parallel()
	// The real peer credentials: this test's process is also the "engine",
	// so its uid is the engine's own and is refused although recorded.
	l := &fakeLedger{}
	c := serve(t, []uint32{uint32(os.Getuid())}, peercred.UID, l)
	conn, err := net.Dial("unix", c.Path)
	require.NoError(t, err)
	defer conn.Close()
	// The refusal comes without the client sending a byte.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	var g person.Greeting
	require.NoError(t, json.Unmarshal([]byte(line), &g))
	require.False(t, g.OK)
	require.Equal(t, person.CodeUIDNotAllowed, g.Error.Code)
	require.Zero(t, l.calls.Load())
}

func TestAMissingSocketIsAnEngineNotRunning(t *testing.T) {
	t.Parallel()
	c := person.Client{Path: filepath.Join(t.TempDir(), "person.sock")}
	_, err := c.Pages(context.Background())
	require.ErrorIs(t, err, person.ErrNotRunning)
	require.NotContains(t, err.Error(), "permission denied")
	require.NotContains(t, err.Error(), "no such file")
}

func TestAListenerThatIsGoneIsAnEngineNotRunning(t *testing.T) {
	t.Parallel()
	path := socketPath(t)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	ln.SetUnlinkOnClose(false)
	require.NoError(t, ln.Close()) // the file stays, nobody listens
	_, err = person.Client{Path: path}.Pages(context.Background())
	require.ErrorIs(t, err, person.ErrNotRunning)
}

// rawCall sends one raw request line as an admitted person and returns the
// response.
func rawCall(t *testing.T, c person.Client, line string) person.Response {
	t.Helper()
	conn, err := net.Dial("unix", c.Path)
	require.NoError(t, err)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	greeting, err := r.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, greeting, `"ok":true`)
	_, _ = conn.Write([]byte(line))
	raw, err := r.ReadString('\n')
	require.NoError(t, err)
	var resp person.Response
	require.NoError(t, json.Unmarshal([]byte(raw), &resp))
	return resp
}

func TestThePersonSocketRefusesMalformedRequests(t *testing.T) {
	t.Parallel()
	l := &fakeLedger{}
	c := serve(t, []uint32{personUID}, peerIs(personUID), l)
	cases := []struct {
		name, line string
		code       person.Code
	}{
		{"an unknown key", `{"method":"PAGES","agent":"bot","params":{},"extra":1}` + "\n", person.CodeInvalidArgument},
		{"an unknown param", `{"method":"LIST_PASSKEYS","agent":"bot","params":{"all":true}}` + "\n", person.CodeInvalidArgument},
		{"an unknown method", `{"method":"QUERY","agent":"bot","params":{"sql":"select 1"}}` + "\n", person.CodeUnknownMethod},
		{"an MCP tool name", `{"method":"write","agent":"bot","params":{}}` + "\n", person.CodeUnknownMethod},
		{"an unknown agent", `{"method":"LIST_PASSKEYS","agent":"other","params":{}}` + "\n", person.CodeUnknownAgent},
		{"a bad scope", `{"method":"PREVIEW_REVERT","agent":"bot","params":{"scope":"TABLE","id":"` + uuid.NewString() + `"}}` + "\n", person.CodeInvalidArgument},
		{"too many change ids", `{"method":"ROW_CHANGES","agent":"bot","params":{"changeIds":[` + strings.TrimSuffix(strings.Repeat(`"`+uuid.NewString()+`",`, pagination.MaxLimit+1), ",") + `]}}` + "\n", person.CodeInvalidArgument},
		{"a request over the size limit", `{"method":"PAGES","agent":"` + strings.Repeat("a", person.MaxRequestBytes) + `"}` + "\n", person.CodeInvalidArgument},
		{"no line end", `{"method":"PAGES"}`, person.CodeInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "no line end" {
				// The engine waits for the newline until the request timeout;
				// close the write side so it sees the end now.
				conn, err := net.Dial("unix", c.Path)
				require.NoError(t, err)
				defer conn.Close()
				r := bufio.NewReader(conn)
				_, err = r.ReadString('\n')
				require.NoError(t, err)
				_, _ = conn.Write([]byte(tc.line))
				require.NoError(t, conn.(*net.UnixConn).CloseWrite())
				raw, err := r.ReadString('\n')
				require.NoError(t, err)
				require.Contains(t, raw, string(tc.code))
				return
			}
			resp := rawCall(t, c, tc.line)
			require.NotNil(t, resp.Error)
			require.Equal(t, tc.code, resp.Error.Code, resp.Error.Message)
		})
	}
	require.Zero(t, l.calls.Load())
}

func TestThePersonSocketMapsErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	l := &fakeLedger{err: ledger.ErrApprovalNotFound}
	_, err := serve(t, []uint32{personUID}, peerIs(personUID), l).Agent("bot").FindApproval(ctx, uuid.New())
	require.ErrorIs(t, err, ledger.ErrApprovalNotFound, "NOT_FOUND is the same-user sentinel")

	l = &fakeLedger{err: &pgconn.PgError{Code: "BS003", Message: "approval refused", Detail: "signature does not verify"}}
	_, err = serve(t, []uint32{personUID}, peerIs(personUID), l).Agent("bot").SubmitApproval(ctx, uuid.New(), passkey.Assertion{})
	var we *person.Error
	require.ErrorAs(t, err, &we)
	require.Equal(t, person.CodeRefused, we.Code)
	require.Equal(t, "approval refused: signature does not verify", err.Error(), "Postgres's message, as the same-user CLI prints it")

	l = &fakeLedger{err: errors.New("dial tcp: user=basalt_agent_bot password=secret")}
	_, err = serve(t, []uint32{personUID}, peerIs(personUID), l).Agent("bot").ListPasskeys(ctx)
	require.ErrorAs(t, err, &we)
	require.Equal(t, person.CodeInternal, we.Code)
	require.NotContains(t, err.Error(), "secret", "no connection detail leaves the engine")
}

func TestThePersonSocketRoundTripsWhatTheCLIPrints(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	used := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	keys := []ledger.Passkey{{
		Credential: passkey.Credential{
			ID: []byte{9, 8, 7}, PublicKey: &key.PublicKey, SignCount: 4,
			Relying: passkey.Relying{RPID: "localhost", Origin: "http://localhost:8787"}, UserHandle: []byte{1},
		},
		Label: "laptop", CreatedAt: used.Add(-time.Hour), LastUsedAt: &used,
	}}
	approval := ledger.Approval{
		ID: uuid.Must(uuid.NewV7()), RunID: uuid.Must(uuid.NewV7()), Rows: 12, Status: "PENDING",
		ExpiresAt: used, BindingText: "binding", Lines: []string{"a", "b"}, Params: json.RawMessage(`[1]`), Assigned: []string{},
	}
	l := &fakeLedger{keys: keys, approval: approval}
	c := serve(t, []uint32{personUID}, peerIs(personUID), l)

	pages, err := c.Pages(ctx)
	require.NoError(t, err)
	require.Equal(t, "http://localhost:8787", pages.PagesURL)
	require.Equal(t, "OFF", pages.UpdateCheck)

	got, err := c.Agent("bot").ListPasskeys(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.True(t, key.PublicKey.Equal(got[0].Credential.PublicKey), "the public key survives the wire")
	got[0].Credential.PublicKey = keys[0].Credential.PublicKey
	require.Equal(t, keys, got)

	a, err := c.Agent("bot").FindApproval(ctx, approval.ID)
	require.NoError(t, err)
	require.Equal(t, approval, a)

	h, err := c.Agent("bot").CheckHealth(ctx, ledger.HealthOptions{Pin: &guard.ChainHead{Seq: 3, Hash: []byte{3}}})
	require.NoError(t, err)
	require.Equal(t, guard.ChainHead{Seq: 7, Hash: []byte{1, 2}}, h.Head)
}

// agentCalls are the 12 agent-scoped calls; PAGES names no agent.
func agentCalls() map[person.Method]func(context.Context, *person.AgentClient) error {
	id := uuid.Must(uuid.NewV7())
	scope := guard.RevertScope{Kind: "RUN", ID: id}
	return map[person.Method]func(context.Context, *person.AgentClient) error{ //nolint:exhaustive // PAGES names no agent
		person.MethodCheckHealth: func(c context.Context, a *person.AgentClient) error {
			_, err := a.CheckHealth(c, ledger.HealthOptions{})
			return err
		},
		person.MethodListChanges: func(c context.Context, a *person.AgentClient) error {
			_, err := a.ListChanges(c, ledger.ChangeListParams{})
			return err
		},
		person.MethodListAccess: func(c context.Context, a *person.AgentClient) error {
			_, err := a.ListAccess(c)
			return err
		},
		person.MethodRowChanges: func(c context.Context, a *person.AgentClient) error {
			_, err := a.RowChanges(c, []uuid.UUID{id})
			return err
		},
		person.MethodListPasskeys: func(c context.Context, a *person.AgentClient) error {
			_, err := a.ListPasskeys(c)
			return err
		},
		person.MethodFindApproval: func(c context.Context, a *person.AgentClient) error {
			_, err := a.FindApproval(c, id)
			return err
		},
		person.MethodSubmitApproval: func(c context.Context, a *person.AgentClient) error {
			_, err := a.SubmitApproval(c, id, passkey.Assertion{})
			return err
		},
		person.MethodFindRevert: func(c context.Context, a *person.AgentClient) error {
			_, err := a.FindRevert(c, id)
			return err
		},
		person.MethodPreviewRevert: func(c context.Context, a *person.AgentClient) error {
			_, err := a.PreviewRevert(c, scope)
			return err
		},
		person.MethodPrepareRevert: func(c context.Context, a *person.AgentClient) error {
			_, err := a.PrepareRevert(c, scope, "undo")
			return err
		},
		person.MethodApplyRevert: func(c context.Context, a *person.AgentClient) error {
			_, err := a.ApplyRevert(c, id, passkey.Assertion{})
			return err
		},
		person.MethodListRevertLines: func(c context.Context, a *person.AgentClient) error {
			_, err := a.ListRevertLines(c, ledger.RevertLineParams{RevertID: id, Params: pagination.Params{Limit: 10}})
			return err
		},
		person.MethodRescopeRevert: func(c context.Context, a *person.AgentClient) error {
			_, err := a.RescopeRevert(c, id, []uuid.UUID{id}, []string{"public.leads"})
			return err
		},
		person.MethodRejectRevert: func(c context.Context, a *person.AgentClient) error {
			_, err := a.RejectRevert(c, id, "not now")
			return err
		},
	}
}

// TestAnAgentSharingThePersonsUIDSeesOnlyItsOwnLedger is owner decision
// SM-4: when the peer is on the allowlist and is also an agent's OS user,
// every call is scoped to that agent; another agent's ledger is refused.
func TestAnAgentSharingThePersonsUIDSeesOnlyItsOwnLedger(t *testing.T) {
	t.Parallel()
	require.Len(t, agentCalls(), 14, "every agent-scoped method")
	for m, call := range agentCalls() {
		t.Run(string(m), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			bot, other := &fakeLedger{}, &fakeLedger{}
			o := person.Options{
				Allow:     []uint32{personUID},
				Agents:    map[string]person.Ledger{"bot": bot, "other": other},
				AgentUIDs: map[string]uint32{"bot": personUID, "other": otherUID},
			}

			// The peer runs bot: bot is served, other is refused unread.
			o.PeerUID = peerIs(personUID)
			c := serveWith(t, o)
			require.NoError(t, call(ctx, c.Agent("bot")), "its own agent")
			require.Equal(t, int32(1), bot.calls.Load())
			err := call(ctx, c.Agent("other"))
			var we *person.Error
			require.ErrorAs(t, err, &we)
			require.Equal(t, person.CodeAgentNotAllowed, we.Code)
			require.Contains(t, we.Message, "basalt init --os-user")
			require.Zero(t, other.calls.Load(), "another agent's ledger is never reached")
			err = call(ctx, c.Agent("nobody"))
			require.ErrorAs(t, err, &we)
			require.Equal(t, person.CodeAgentNotAllowed, we.Code, "no probing for agent names")
			_, err = c.Pages(ctx)
			require.NoError(t, err, "PAGES names no agent")

			// A person who runs no agent sees every agent.
			o.Allow, o.PeerUID = []uint32{agentUID}, peerIs(agentUID)
			p := serveWith(t, o)
			require.NoError(t, call(ctx, p.Agent("bot")))
			require.NoError(t, call(ctx, p.Agent("other")))
		})
	}
}

func TestAPeerRunningTwoAgentsReachesExactlyThoseTwo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	one, two, third := &fakeLedger{}, &fakeLedger{}, &fakeLedger{}
	c := serveWith(t, person.Options{
		Allow:     []uint32{personUID},
		Agents:    map[string]person.Ledger{"one": one, "two": two, "third": third},
		AgentUIDs: map[string]uint32{"one": personUID, "two": personUID, "third": agentUID},
		PeerUID:   peerIs(personUID),
	})
	for _, name := range []string{"one", "two"} {
		_, err := c.Agent(name).ListPasskeys(ctx)
		require.NoError(t, err, name)
	}
	_, err := c.Agent("third").ListPasskeys(ctx)
	var we *person.Error
	require.ErrorAs(t, err, &we)
	require.Equal(t, person.CodeAgentNotAllowed, we.Code)
	require.Equal(t, int32(1), one.calls.Load())
	require.Equal(t, int32(1), two.calls.Load())
	require.Zero(t, third.calls.Load())
}

func TestListAccessOverSocket(t *testing.T) {
	t.Parallel()
	want := pgcatalog.Access{
		Read:       []string{"public.leads", "public.orders"},
		Write:      []string{"public.leads"},
		NotGranted: []string{"auth.users"},
	}
	c := serve(t, []uint32{personUID}, peerIs(personUID), &fakeLedger{access: want})
	got, err := c.Agent("bot").ListAccess(context.Background())
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestListAccessEmptyListsStayLists(t *testing.T) {
	t.Parallel()
	c := serve(t, []uint32{personUID}, peerIs(personUID), &fakeLedger{})
	got, err := c.Agent("bot").ListAccess(context.Background())
	require.NoError(t, err)
	require.NotNil(t, got.Read)
	require.NotNil(t, got.Write)
	require.NotNil(t, got.NotGranted)
}
