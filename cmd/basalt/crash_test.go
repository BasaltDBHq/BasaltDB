package main

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/crash"
)

// leakedConn is built from parts so no secret scanner reads it as a
// committed credential.
var leakedConn = "postgres" + "://admin" + ":hunter2pass" + "@db.internal.example/prod"

// panicSecret stands for what a command was working on when it panicked.
const panicSecret = "SELECT card_number FROM payments WHERE owner = 'alice@example.com'"

func crashIO(t *testing.T, h *fakeHost, env map[string]string, interactive bool) (*cliIO, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errw bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &out, err: &errw}, func(k string) string { return env[k] })
	c.host, c.interactive, c.goos = h, interactive, "linux"
	return c, &out, &errw
}

// saveCrash saves a report the way a panicking command does, into the
// person's directory under h.
func saveCrash(t *testing.T, h *fakeHost) crash.Report {
	t.Helper()
	rec := crash.Recorder{
		Dir: filepath.Join(h.configDir, perUserDirName, crash.DirName), Version: "0.0.1", Scrub: crash.OSScrubber(), Now: time.Now,
	}
	var stack []byte
	func() {
		defer func() { _ = recover(); stack = debug.Stack() }()
		panic(panicSecret)
	}()
	rep, err := rec.Save(crash.Input{Command: "log", Kind: crash.KindPanic, ErrorCode: "INTERNAL", Value: panicSecret, Stack: stack})
	require.NoError(t, err)
	return rep
}

func TestCrashListShowReport(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)

	c, out, _ := crashIO(t, h, nil, true)
	require.Equal(t, exitOK, runCrash(c, []string{"list"}))
	require.Contains(t, out.String(), "No crash reports")

	rep := saveCrash(t, h)

	c, out, _ = crashIO(t, h, nil, true)
	require.Equal(t, exitOK, runCrash(c, []string{"list"}))
	require.Contains(t, out.String(), rep.ID)

	c, out, _ = crashIO(t, h, nil, true)
	require.Equal(t, exitOK, runCrash(c, []string{"show", rep.ID}))
	require.Equal(t, rep.Show(), out.String())
	require.NotContains(t, out.String(), "card_number")
	require.NotContains(t, out.String(), "alice@example.com")

	// At a terminal it opens the pre-filled issue and prints no link.
	c, out, _ = crashIO(t, h, nil, true)
	require.Equal(t, exitOK, runCrash(c, []string{"report", rep.ID}))
	require.Len(t, h.opened, 1)
	require.True(t, strings.HasPrefix(h.opened[0], "https://github.com/BasaltDBHq/BasaltDB/issues/new?"))
	u, err := url.Parse(h.opened[0])
	require.NoError(t, err)
	require.Contains(t, u.Query().Get("body"), rep.ID)
	require.NotContains(t, out.String(), "https://")

	// Without a terminal it prints the link and opens nothing.
	h.opened = nil
	c, out, _ = crashIO(t, h, nil, false)
	require.Equal(t, exitOK, runCrash(c, []string{"report", rep.ID}))
	require.Empty(t, h.opened)
	require.Contains(t, out.String(), "https://github.com/BasaltDBHq/BasaltDB/issues/new?")

	// A browser that will not open falls back to printing it.
	h.openErr = os.ErrNotExist
	c, out, _ = crashIO(t, h, nil, true)
	require.Equal(t, exitOK, runCrash(c, []string{"report", rep.ID}))
	require.Contains(t, out.String(), "issues/new?")
}

func TestCrashReportOpensNothingUnderAnAgent(t *testing.T) {
	t.Parallel()
	for _, marker := range agentMarkers {
		for _, interactive := range []bool{true, false} {
			h := newFakeHost(t)
			rep := saveCrash(t, h)
			c, out, errw := crashIO(t, h, map[string]string{marker: "1"}, interactive)
			require.Equal(t, exitOK, runCrash(c, []string{"report", rep.ID}), marker)
			require.Empty(t, h.opened, marker)
			require.NotContains(t, out.String()+errw.String(), "issues/new")
			require.Contains(t, out.String(), "basalt crash report "+rep.ID)
			require.Contains(t, out.String(), "terminal of their own")
		}
	}
}

func TestCrashUsageAndUnknownID(t *testing.T) {
	t.Parallel()
	h := newFakeHost(t)
	for _, args := range [][]string{{}, {"nope"}, {"show"}, {"show", "a", "b"}, {"report"}} {
		c, _, _ := crashIO(t, h, nil, true)
		require.Equal(t, exitUsage, runCrash(c, args), args)
	}
	c, _, errw := crashIO(t, h, nil, true)
	require.Equal(t, exitError, runCrash(c, []string{"show", "0190aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"}))
	require.Contains(t, errw.String(), "no crash report has that id")
}

// TestAPanicInACommandIsSavedAndScrubbed: a command that panics ends with one
// stderr line naming the report, and nothing the panic carried is saved.
func TestAPanicInACommandIsSavedAndScrubbed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("PGPASSWORD", "envsecretvalue99")

	var errw bytes.Buffer
	code := guarded([]string{"log", "--agent", "bot"}, stdio{err: &errw}, func() int {
		panic("connect " + leakedConn + " envsecretvalue99 " + panicSecret)
	})
	require.Equal(t, exitError, code)
	line := errw.String()
	require.Equal(t, 1, strings.Count(line, "\n"), line)
	require.Contains(t, line, "basalt crash show ")
	require.Contains(t, line, "basalt crash report ")

	base, err := os.UserConfigDir()
	require.NoError(t, err)
	reports := crash.List(filepath.Join(base, perUserDirName, crash.DirName))
	require.Len(t, reports, 1)
	text := reports[0].Show()
	for _, bad := range []string{"hunter2pass", "db.internal.example", "envsecretvalue99", "card_number", "alice@example.com", home} {
		require.NotContains(t, text, bad)
		require.NotContains(t, line, bad)
	}
	require.Equal(t, "log", reports[0].Command)
	require.Contains(t, reports[0].Stack, "TestAPanicInACommandIsSavedAndScrubbed")
}

func TestCommandNameIsOnlyAKnownCommand(t *testing.T) {
	t.Parallel()
	require.Equal(t, "log", commandName([]string{"log", "--agent", "x"}))
	require.Empty(t, commandName([]string{"post" + "gres://u" + ":p@h/db"}))
	require.Empty(t, commandName(nil))
}
