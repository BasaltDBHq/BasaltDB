package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/internal/revert"
)

// evil is text an agent or its data can put in the ledger: erase the line
// and move up (CSI), set the window title (OSC, BEL), write the clipboard
// (OSC 52), a C1 CSI and DEL.
const evil = "x\x1b[2K\x1b[1A\x1b]0;title\x07\x1b]52;c;aGk=\x1b\\\u009b\x7f"

// requireTerminalSafe fails when out holds a control character a terminal
// acts on: every C0 control but line feed and tab, DEL, and the C1
// controls.
func requireTerminalSafe(t *testing.T, out string) {
	t.Helper()
	for _, r := range out {
		unsafe := (r < 0x20 && r != '\n' && r != '\t') || (r >= 0x7f && r <= 0x9f)
		require.False(t, unsafe, "raw U+%04X in %q", r, out)
	}
	require.Contains(t, out, "<U+001B>", "the escape shows as text")
}

func TestTerminalTextKeepsLinesAndTabsAndEscapesControls(t *testing.T) {
	t.Parallel()
	require.Equal(t,
		"a\nb\tc<U+001B>[2K<U+001B>]0;t<U+0007><U+007F><U+009B>d<U+000D><U+202E><0xFF>",
		terminalText("a\nb\tc\x1b[2K\x1b]0;t\x07\x7f\u009bd\r\u202e\xff"))
	require.Equal(t, "note 5 — 日本 🚀 José\n", terminalText("note 5 — 日本 🚀 José\n"))
}

func TestLogTextEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 11, 6, 2, 11, 0, time.UTC)
	id := uuid.Must(uuid.NewV7())
	changes := []ledger.Change{
		{ID: id, At: at, Op: "UPDATE", Status: "REFUSED", Table: "public.le" + evil, Intent: "fix typo" + evil,
			Code: "ROW_LIMIT_EXCEEDED", Reason: "too many rows " + evil},
		{ID: uuid.Must(uuid.NewV7()), At: at, Op: "SELECT", Status: "APPLIED", Table: "public.a" + evil},
		{ID: uuid.Must(uuid.NewV7()), At: at, Op: "SELECT", Status: "APPLIED", Table: "public.b"},
	}
	rows := map[uuid.UUID][]ledger.RowChange{id: {{
		Table: "public.le" + evil, Op: "UPDATE",
		Key:    map[string]any{"id": "1" + evil},
		Before: map[string]any{"note" + evil: "old"},
		After:  map[string]any{"note" + evil: "new" + evil},
	}}}
	for _, full := range []bool{false, true} {
		var out bytes.Buffer
		printText(&cliIO{ctx: context.Background(), stdout: &out}, changes, rows, full)
		requireTerminalSafe(t, out.String())
		require.Len(t, strings.Split(strings.TrimSpace(out.String()), "\n"), map[bool]int{false: 4, true: 5}[full])
	}
}

func TestLogWarningsEscapeControlCharacters(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	c := &cliIO{ctx: context.Background(), stderr: &errOut}
	warn(c, ledger.Health{
		Chain:     guard.ChainStatus{Intact: true},
		Uncovered: []guard.Uncovered{{Table: "public.t" + evil, Why: "no trigger" + evil}},
		RLSBlind:  []string{"public.r" + evil},
		DeadMan:   &ledger.DeadMan{LastHeartbeat: "2026" + evil, SilentHours: 3},
	})
	printPII(c, &ledger.PIIHealth{
		Unclassified: 1, UnclassifiedNames: []string{"public.t.c" + evil},
		Review: 1, ReviewNames: []string{"public.t.d" + evil},
		Dictionary: &ledger.DictionaryHealth{},
	}, "")
	requireTerminalSafe(t, errOut.String())
}

func TestRevertStatusEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	c := &cliIO{ctx: context.Background(), stdout: &out}
	conflict := "CHANGED_AFTER" + evil
	printRevertStatus(c, revertStatusDTO{
		RevertID: uuid.NewString(), Status: "APPLIED" + evil, Batched: true,
		SkippedLines: []skippedLineDTO{{Conflict: conflict, Plan: revert.Line{Op: "UPDATE", Table: "public.t" + evil}}},
	})
	requireTerminalSafe(t, out.String())
}

func TestStatusEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	printStatus(&out, statusOut{StatusReport: agent.StatusReport{Agent: "bot" + evil, Problems: []agent.Problem{{
		Code: "GUARD_OUTDATED", Severity: "ERROR", Message: "table public.t" + evil,
		PersonMessage: "first line\nsecond" + evil,
		NextSteps:     []agent.NextStep{{Command: "basalt init" + evil}},
	}}}})
	requireTerminalSafe(t, out.String())
	require.Contains(t, out.String(), "      first line\n      second", "a person message keeps its lines")
}

func TestAccessEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	cmds, err := agent.NewCommands("bot", "", "linux", []string{"--write=public.leads"})
	require.NoError(t, err)
	var out strings.Builder
	printAccess(&out, pgcatalog.Access{
		Read: []string{"public.r" + evil}, Write: []string{"other.w" + evil}, NotGranted: []string{"public.n" + evil},
	}, cmds, true)
	requireTerminalSafe(t, out.String())
}

func TestFailEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	c := &cliIO{ctx: context.Background(), stderr: &errOut}
	err := errors.New("cannot revert: duplicate key: Key (email)=(" + evil + "\nbasalt: reverted: 3 rows restored, 0 left as they are)")
	require.Equal(t, exitError, c.fail(err))
	out := errOut.String()
	requireTerminalSafe(t, out)
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "basalt: cannot revert"), lines[0])
	require.Equal(t, "  basalt: reverted: 3 rows restored, 0 left as they are)", lines[1],
		"a line from the error is indented, so it cannot pass for a line basalt printed")
}

func TestApprovalStatusEscapesControlCharacters(t *testing.T) {
	t.Parallel()
	line := approvalStatusLine(uuid.Nil, "EXPIRED"+evil+"\nbasalt: approval signed")
	requireTerminalSafe(t, line)
	require.NotContains(t, line, "\n")
}
