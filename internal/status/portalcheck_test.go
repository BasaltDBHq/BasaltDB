package status

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

func checker(dir string, rep *Report, err error) *Checker {
	c := New(PortalverifyOptions{Base: "https://portal.example"}, dir, slog.New(slog.DiscardHandler), func() time.Time { return t0 })
	c.verify = func(context.Context, PortalverifyOptions) (*Report, error) { return rep, err }
	return c
}

func report(files ...File) *Report {
	return &Report{PortalURL: "https://portal.example", Files: files}
}

func TestEachMismatchStatusIsAMismatch(t *testing.T) {
	t.Parallel()
	for _, status := range []string{StatusDiffers, StatusMissing, StatusHeader, StatusUnexpected} {
		res := checker("", report(
			File{Path: "style.css", Status: StatusOK},
			File{Path: "lib/x.js", Status: status},
		), nil).Check(context.Background())
		require.True(t, res.Mismatch(), status)
		require.Equal(t, "1 "+status, res.Summary())
		require.Equal(t, "lib/x.js", res.Findings[0].Path)
	}
}

func TestACleanPortalAndAnUncheckedOneAreNoMismatch(t *testing.T) {
	t.Parallel()
	clean := checker("", report(File{Path: "style.css", Status: StatusOK}), nil).Check(context.Background())
	require.False(t, clean.Mismatch())

	unchecked := checker("", report(File{Path: "style.css", Status: StatusError, Detail: "timeout"}), nil).Check(context.Background())
	require.False(t, unchecked.Mismatch(), "a network error is not a finding")
	require.Equal(t, 1, unchecked.Unchecked)

	failed := checker("", nil, errors.New("boom")).Check(context.Background())
	require.False(t, failed.Mismatch())
	require.Equal(t, "boom", failed.Error)
}

func TestSummaryCountsInAFixedOrder(t *testing.T) {
	t.Parallel()
	res := checker("", report(
		File{Path: "a", Status: StatusMissing},
		File{Path: "b", Status: StatusDiffers},
		File{Path: "c", Status: StatusDiffers},
	), nil).Check(context.Background())
	require.Equal(t, "2 DIFFERS, 1 MISSING", res.Summary())
}

func TestFindingsAreCapped(t *testing.T) {
	t.Parallel()
	files := make([]File, 0, maxFindings+5)
	for i := range maxFindings + 5 {
		files = append(files, File{Path: string(rune('a'+i%26)) + "/" + time.Duration(i).String(), Status: StatusDiffers})
	}
	res := checker("", report(files...), nil).Check(context.Background())
	require.Len(t, res.Findings, maxFindings)
	require.Equal(t, maxFindings+5, res.Total)
	require.Contains(t, res.Summary(), "(and 5 more)")
}

func TestLastIsEmptyBeforeTheFirstCheckAndKeepsTheLatest(t *testing.T) {
	t.Parallel()
	c := checker("", report(File{Path: "a", Status: StatusDiffers}), nil)
	_, ok := c.Last()
	require.False(t, ok)
	c.Check(context.Background())
	got, ok := c.Last()
	require.True(t, ok)
	require.True(t, got.Mismatch())
	require.Equal(t, t0, got.CheckedAt)
}

func TestRunChecksAtOnceAndAgainEachInterval(t *testing.T) {
	t.Parallel()
	calls := make(chan struct{}, 8)
	c := New(PortalverifyOptions{Base: "https://portal.example"}, "", slog.New(slog.DiscardHandler), time.Now)
	c.verify = func(context.Context, PortalverifyOptions) (*Report, error) {
		calls <- struct{}{}
		return report(), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, 10*time.Millisecond); close(done) }()
	for range 3 {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("the check did not repeat")
		}
	}
	cancel()
	<-done
}

// TestTheResultIsSavedOwnerOnly: a check saves its result in the state
// directory, readable by the engine's user only.
func TestTheResultIsSavedOwnerOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	checker(dir, report(File{Path: "a", Status: StatusDiffers}), nil).Check(context.Background())

	st, err := os.Stat(filepath.Join(dir, fileName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}
