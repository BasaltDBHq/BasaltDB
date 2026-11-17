package guard_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
)

var reinstallT0 = time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)

// inst is the test install id n: the same n, the same install, and a
// larger n sorts after a smaller one.
func inst(n byte) uuid.UUID { return uuid.UUID{15: n} }

func minutesIn(minutes int) time.Time { return reinstallT0.Add(time.Duration(minutes) * time.Minute) }

func agents(r guard.Reinstall) []string {
	out := make([]string, 0, len(r.Reports))
	for _, rep := range r.Reports {
		out = append(out, rep.Agent)
	}
	return out
}

// The reader's own report comes first, then the other agents' earliest
// reports, oldest first, at most guard.MaxReinstallAgents, each with a count
// of its further reports.
func TestAssembleReinstallsOrdersReports(t *testing.T) {
	t.Parallel()
	rows := make([]guard.ReportRow, 0, 8)
	rows = append(rows,
		guard.ReportRow{Install: inst(9), Agent: "me", At: minutesIn(5), Seq: 50, Count: 1},
		guard.ReportRow{Install: inst(9), Agent: "early", At: minutesIn(1), Seq: 10, Count: 4},
	)
	for i := range 6 {
		rows = append(rows, guard.ReportRow{Install: inst(9), Agent: fmt.Sprintf("late%d", i), At: minutesIn(10 + i), Seq: 60, Count: 1})
	}
	rs := guard.AssembleReinstalls("me", rows, nil, nil)
	require.Len(t, rs.List, 1)
	r := rs.List[0]
	require.Equal(t, []string{"me", "early", "late0", "late1", "late2", "late3"}, agents(r))
	require.Equal(t, 2, r.MoreAgents)
	require.Equal(t, 3, r.Reports[1].More)
	require.Nil(t, r.InstalledAt)
	require.True(t, minutesIn(1).Equal(r.FirstReportedAt()))

	// Without a report of its own, the reader sees the earliest first.
	rs = guard.AssembleReinstalls("someone-else", rows[:2], nil, nil)
	require.Equal(t, []string{"early", "me"}, agents(rs.List[0]))
}

// Reinstalls are newest first (by the install's time, or the first report
// without an install record), at most guard.MaxReinstalls.
func TestAssembleReinstallsNewestFirst(t *testing.T) {
	t.Parallel()
	recs := map[uuid.UUID]guard.InstallRecord{
		inst(1): {At: minutesIn(0), By: "admin"},
		inst(2): {At: minutesIn(100), By: "admin", VaultUser: "alice"},
		inst(4): {At: minutesIn(300), By: "admin"},
	}
	rows := make([]guard.ReportRow, 0, 5)
	for i, install := range []uuid.UUID{inst(1), inst(2), inst(3), inst(4), inst(5)} {
		rows = append(rows, guard.ReportRow{Install: install, Agent: "bot", At: minutesIn(50 + 100*i), Count: 1})
	}
	rs := guard.AssembleReinstalls("bot", rows, recs, nil)
	got := make([]uuid.UUID, 0, len(rs.List))
	for _, r := range rs.List {
		got = append(got, r.Install)
	}
	// 5: reported at 450; 4: installed at 300; 3: reported at 250.
	require.Equal(t, []uuid.UUID{inst(5), inst(4), inst(3)}, got)
	require.Equal(t, 2, rs.Earlier)
}

// The kept copy adds the reader's reports: of an install the ledger no
// longer shows, and earlier than what it does show.
func TestAssembleReinstallsMergesTheKeptCopy(t *testing.T) {
	t.Parallel()
	rows := []guard.ReportRow{{Install: inst(7), Agent: "me", At: minutesIn(20), Seq: 70, Count: 1}}
	kept := []guard.SetAside{
		{PinnedSeq: 60, PinnedHash: []byte{6}, PinnedInstall: inst(6), Install: inst(7), At: minutesIn(10)},
		{PinnedSeq: 61, PinnedHash: []byte{6}, PinnedInstall: inst(6), Install: inst(7), At: minutesIn(15)},
		{PinnedSeq: 80, PinnedHash: []byte{8}, PinnedInstall: inst(7), Install: inst(8), At: minutesIn(30)},
	}
	rs := guard.AssembleReinstalls("me", rows, map[uuid.UUID]guard.InstallRecord{inst(7): {At: minutesIn(0), By: "admin"}}, kept)
	require.Len(t, rs.List, 2)
	deleted, seven := rs.List[0], rs.List[1]
	require.Equal(t, inst(8), deleted.Install, "a reinstall whose rows are gone still shows")
	require.Nil(t, deleted.InstalledAt)
	require.Equal(t, int64(80), deleted.Reports[0].PinnedSeq)
	require.Equal(t, "me", deleted.Reports[0].Agent)

	require.Equal(t, inst(7), seven.Install)
	require.Len(t, seven.Reports, 1)
	require.Equal(t, int64(60), seven.Reports[0].PinnedSeq, "the earlier kept report")
	require.Equal(t, 1, seven.Reports[0].More)
}
