package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/agentdb"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// A reveal racing the approval's signature or apply, or the revert's
// signature, serializes on the item's row lock (plan task 5): whichever
// takes the lock second gets the item's normal answer, and neither
// deadlocks. The order is made, not timed: an admin transaction holds the
// item's row, the first call is started and seen waiting on the lock
// (pg_stat_activity), then the second, and the row is let go. Postgres
// grants a row lock to its waiters in turn.

const dropLeadSQL = `DELETE FROM public.leads WHERE id = $1`

// raceEnv: bot may read and write leads only; its held deletes cascade to
// notes it cannot read. Calls go through the engine's agentdb store.
type raceEnv struct {
	d      *guardtest.DB
	store  *agentdb.Store
	person *passkeytest.Authenticator
}

func newRaceEnv(t *testing.T) raceEnv {
	t.Helper()
	ctx := context.Background()
	d := guardtest.New(t).WithDemo(t)
	leads := []string{"public.leads"}
	bot := d.NewAgent(t, "bot", leads, leads)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, d.Admin, person.Credential(), "app"))
	pool, err := agentdb.NewPool(ctx, bot.URL, 4)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return raceEnv{d: d, store: agentdb.NewStore(pool, sqlguard.DefaultLimits(), time.Now), person: person}
}

// heldDelete is a held delete of one lead and the run it belongs to.
type heldDelete struct {
	in     guard.Intent
	params []any
	held   guard.Held
}

func (e raceEnv) hold(t *testing.T, lead int) heldDelete {
	t.Helper()
	ctx := context.Background()
	in := guard.Intent{RunID: uuid.Must(uuid.NewV7()), Text: "Drop lead " + strconv.Itoa(lead)}
	require.NoError(t, e.store.StartRun(ctx, in))
	params := []any{json.Number(strconv.Itoa(lead))}
	lines, err := e.store.Preview(ctx, in, dropLeadSQL, params, []string{})
	require.NoError(t, err)
	held, err := e.store.Hold(ctx, in, guard.HoldRequest{Statement: dropLeadSQL, Params: params, Assigned: []string{}, Lines: lines})
	require.NoError(t, err)
	return heldDelete{in: in, params: params, held: held}
}

// signature is the person's signature of a held write; sign relays it.
func (e raceEnv) signature(t *testing.T, h heldDelete) passkey.Assertion {
	t.Helper()
	as, err := e.person.Sign(approval.Challenge(h.held.BindingText), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return as
}

func (e raceEnv) sign(h heldDelete, as passkey.Assertion) error {
	_, err := e.store.SubmitApproval(context.Background(), h.held.ApprovalID, as)
	return err
}

func (e raceEnv) apply(h heldDelete) error {
	_, err := e.store.WriteApproved(context.Background(), h.in, h.held.ApprovalID, sqlguard.OpDelete, dropLeadSQL, h.params)
	return err
}

// proof is the person's reveal proof for an item, with the key the engine
// derives from the page's reveal secret.
func (e raceEnv) proof(t *testing.T, kind string, id uuid.UUID, table, idCol string) (passkey.Assertion, []byte) {
	t.Helper()
	var nonce, rowsHash []byte
	require.NoError(t, e.d.Admin.QueryRow(context.Background(),
		`SELECT reveal_nonce, rows_hash FROM basalt_meta.`+table+` WHERE `+idCol+` = $1`, id).Scan(&nonce, &rowsHash))
	key, err := approval.RevealKey(make([]byte, links.SecretBytes))
	require.NoError(t, err)
	ch, err := approval.RevealChallenge(kind, id, nonce, key, hexOf(rowsHash))
	require.NoError(t, err)
	as, err := e.person.Sign(ch, passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return as, key
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// revealApproval is the engine's approval reveal with the person's proof:
// open_reveal (which locks the approval row), then the re-run preview.
func (e raceEnv) revealApproval(h heldDelete, as passkey.Assertion, key []byte) ([]approval.RevealedRow, error) {
	ticket, err := e.store.OpenReveal(context.Background(), h.held.ApprovalID, as, key)
	if err != nil {
		return nil, err
	}
	return e.store.RevealPreview(context.Background(), h.in, sqlguard.OpDelete, dropLeadSQL, h.params, h.held.ApprovalID, ticket)
}

// lockRow locks one row of a basalt_meta table in a transaction on its own
// admin connection; the returned func lets it go.
func (e raceEnv) lockRow(t *testing.T, table, idCol string, id uuid.UUID) func() {
	t.Helper()
	ctx := context.Background()
	conn, err := pgdial.Connect(ctx, e.d.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(ctx) })
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `SELECT 1 FROM basalt_meta.`+table+` WHERE `+idCol+` = $1 FOR UPDATE`, id)
	require.NoError(t, err)
	return func() { require.NoError(t, tx.Rollback(ctx)) }
}

// waitingOnLocks blocks until n sessions of this database wait on a lock.
func (e raceEnv) waitingOnLocks(t *testing.T, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting int
		err := e.d.Admin.QueryRow(context.Background(), `SELECT count(pid)::int FROM pg_catalog.pg_stat_activity
			WHERE datname = pg_catalog.current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
		return err == nil && waiting >= n
	}, 10*time.Second, 5*time.Millisecond, "%d calls should wait on the item's row lock", n)
}

// race runs first, then second, both queued on the item's row lock held by
// lockRow, and returns their errors once both finished.
func (e raceEnv) race(t *testing.T, release func(), first, second func() error) (error, error) {
	t.Helper()
	done1, done2 := make(chan error, 1), make(chan error, 1)
	go func() { done1 <- first() }()
	e.waitingOnLocks(t, 1)
	go func() { done2 <- second() }()
	e.waitingOnLocks(t, 2)
	release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var err1, err2 error
	for range 2 {
		select {
		case err1 = <-done1:
			done1 = nil
		case err2 = <-done2:
			done2 = nil
		case <-ctx.Done():
			t.Fatal("a call never finished: deadlock")
		}
	}
	return err1, err2
}

func requireRefused(t *testing.T, err error, code guard.Code, detail string) {
	t.Helper()
	got, ok := guard.CodeOf(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, code, got)
	var pe *pgconn.PgError
	require.True(t, errors.As(err, &pe))
	require.Equal(t, detail, pe.Detail)
	require.NotEqual(t, "40P01", pe.Code, "no deadlock")
}

// Approval: a reveal against the person's signature, and against the
// apply of a signed approval, in both orders. Proofs and signatures are
// made before the race: the calls themselves only touch the database.
func TestRevealRacesTheApproval(t *testing.T) {
	t.Parallel()
	e := newRaceEnv(t)
	lock := func(h heldDelete) func() { return e.lockRow(t, "approvals", "approval_id", h.held.ApprovalID) }
	proof := func(h heldDelete) (passkey.Assertion, []byte) {
		return e.proof(t, approval.KindApprove, h.held.ApprovalID, "approvals", "approval_id")
	}
	signed := func(lead int) heldDelete {
		h := e.hold(t, lead)
		require.NoError(t, e.sign(h, e.signature(t, h)))
		return h
	}

	// The reveal first: only open_reveal's wait on the approval row is
	// ordered. After it commits, the reveal's second transaction reads
	// the approval unlocked, so whether it reads before or after the
	// signature commits is timing: it shows the rows, or gets the
	// approval's normal answer. Either way no deadlock, and the signature
	// after it counts.
	h := e.hold(t, 20)
	as, key := proof(h)
	sig := e.signature(t, h)
	var rows []approval.RevealedRow
	errReveal, errSign := e.race(t, lock(h), func() error {
		var err error
		rows, err = e.revealApproval(h, as, key)
		return err
	}, func() error { return e.sign(h, sig) })
	if errReveal == nil {
		require.Len(t, rows, 2, "notes 39 and 40")
	} else {
		requireRefused(t, errReveal, guard.CodeApprovalInvalid, "approval already approved")
	}
	require.NoError(t, errSign)
	require.NoError(t, e.apply(h), "the signed write applies")

	// The signature first: the reveal gets the approval's normal answer.
	h = e.hold(t, 19)
	as, key = proof(h)
	sig = e.signature(t, h)
	errSign, errReveal = e.race(t, lock(h), func() error { return e.sign(h, sig) }, func() error {
		_, err := e.revealApproval(h, as, key)
		return err
	})
	require.NoError(t, errSign)
	requireRefused(t, errReveal, guard.CodeApprovalInvalid, "approval already approved")

	// A signed approval: its apply first, the reveal after it is refused
	// as used.
	h = signed(18)
	as, key = proof(h)
	errApply, errReveal := e.race(t, lock(h), func() error { return e.apply(h) }, func() error {
		_, err := e.revealApproval(h, as, key)
		return err
	})
	require.NoError(t, errApply, "APPLIED")
	requireRefused(t, errReveal, guard.CodeApprovalInvalid, "approval already used")

	// The reveal first: refused (the approval is signed), and the apply
	// after it still lands.
	h = signed(17)
	as, key = proof(h)
	errReveal, errApply = e.race(t, lock(h), func() error {
		_, err := e.revealApproval(h, as, key)
		return err
	}, func() error { return e.apply(h) })
	requireRefused(t, errReveal, guard.CodeApprovalInvalid, "approval already approved")
	require.NoError(t, errApply, "APPLIED")
	var left int
	require.NoError(t, e.d.Admin.QueryRow(context.Background(),
		`SELECT count(id)::int FROM public.leads WHERE id IN (17, 18, 20)`).Scan(&left))
	require.Zero(t, left, "every applied delete landed")
}

// Revert: a reveal against the person's signature (apply_revert), in both
// orders.
func TestRevealRacesTheRevertSignature(t *testing.T) {
	t.Parallel()
	e := newRaceEnv(t)
	prepared := func(lead int) guard.PreparedRevert {
		h := e.hold(t, lead)
		require.NoError(t, e.sign(h, e.signature(t, h)))
		require.NoError(t, e.apply(h))
		prep, err := e.store.PrepareRevert(context.Background(), guard.RevertScope{Kind: revert.ScopeRun, ID: h.in.RunID}, "Undo it", time.Minute)
		require.NoError(t, err)
		return prep
	}
	// The proof and the signature are made before each race.
	type signed struct {
		proof passkey.Assertion
		key   []byte
		sig   passkey.Assertion
	}
	made := func(prep guard.PreparedRevert) signed {
		as, key := e.proof(t, approval.KindRevert, prep.RevertID, "reverts", "revert_id")
		sig, err := e.person.Sign(revert.Challenge(prep.BindingText), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		return signed{proof: as, key: key, sig: sig}
	}
	reveal := func(prep guard.PreparedRevert, m signed) (guard.RevealedRevert, error) {
		return e.store.RevealRevertRows(context.Background(), prep.RevertID, m.proof, m.key)
	}
	signRevert := func(prep guard.PreparedRevert, m signed) error {
		_, err := e.store.ApplyRevert(context.Background(), prep.RevertID, m.sig)
		return err
	}
	lock := func(prep guard.PreparedRevert) func() { return e.lockRow(t, "reverts", "revert_id", prep.RevertID) }

	// The reveal first: it shows the rows; the signature after it runs the
	// revert.
	prep := prepared(20)
	m := made(prep)
	var out guard.RevealedRevert
	errReveal, errSign := e.race(t, lock(prep), func() error {
		var err error
		out, err = reveal(prep, m)
		return err
	}, func() error { return signRevert(prep, m) })
	require.NoError(t, errReveal)
	require.False(t, out.RowsChanged)
	require.Len(t, out.Rows, 2)
	require.NoError(t, errSign)

	// The signature first: the reveal gets the revert's normal answer.
	prep = prepared(19)
	m = made(prep)
	errSign, errReveal = e.race(t, lock(prep), func() error { return signRevert(prep, m) }, func() error {
		_, err := reveal(prep, m)
		return err
	})
	require.NoError(t, errSign)
	requireRefused(t, errReveal, guard.CodeRevertInvalid, "revert already applied")
}
