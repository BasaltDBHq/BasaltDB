package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/basaltdbhq/basaltdb/internal/rlspick"
)

// rlsAsk is one row-level security question: a table the agent may be
// given all rows of.
type rlsAsk struct {
	Table string
	Rows  int64
	// Text is the per-table question, asked only where the checklist
	// cannot be (answers piped to a command that reads them one by one).
	Text string
}

// rlsAnswers answers the row-level security questions by --agent-rls: none
// says no to all, all-rows yes to all, a list yes to the tables it names
// (a name that is none of the agent's tables is a usage error, before anything is
// written). ask says no to all when quiet (--yes, --dry-run); otherwise it
// shows the checklist at a terminal, with every table checked, and without
// one prints the grouped list on stderr and reads one line from stdin: all,
// none or a list; an empty line or the end of input is all.
func rlsAnswers(c *cliIO, mode AgentRLSMode, quiet bool, agent string, own []string, asks []rlsAsk) ([]bool, error) {
	out := make([]bool, len(asks))
	entries := make([]rlspick.Entry, len(asks))
	for i, a := range asks {
		entries[i] = rlspick.Entry{Table: a.Table, Rows: a.Rows}
	}
	switch {
	case mode == AgentRLSNone:
		return out, nil
	case mode == AgentRLSAllRows:
		return fill(out, true), nil
	case mode.isList():
		patterns, err := rlspick.ParseList(string(mode))
		if err != nil {
			return nil, fmt.Errorf("%w: --agent-rls: %w", errUsage, err)
		}
		return pickByList(entries, own, patterns, "--agent-rls")
	case quiet || len(asks) == 0:
		return out, nil
	case c.terminal != nil:
		return checklistAnswers(c, agent, asks, entries)
	case c.interactive:
		// Input a test feeds as a terminal: one y/N per table.
		for i, a := range asks {
			ok, err := c.confirm(a.Text)
			if err != nil {
				return nil, err
			}
			out[i] = ok
		}
		return out, nil
	}
	return pipedAnswers(c, agent, own, entries)
}

func fill(b []bool, v bool) []bool {
	for i := range b {
		b[i] = v
	}
	return b
}

// pickByList marks the entries the patterns select; a pattern that selects
// none is a usage error naming it.
func pickByList(entries []rlspick.Entry, own []string, patterns []rlspick.Pattern, what string) ([]bool, error) {
	picked, unknown := rlspick.Match(entries, patterns)
	// A name that is one of the agent's own tables but no longer hidden (a
	// re-run after the policy was added, or RLS off) is fine: only a name
	// outside the agent's tables is an error.
	ownEntries := make([]rlspick.Entry, len(own))
	for i, t := range own {
		ownEntries[i] = rlspick.Entry{Table: t}
	}
	_, unknown = rlspick.Match(ownEntries, unknown)
	if len(unknown) > 0 {
		names := make([]string, len(unknown))
		for i, p := range unknown {
			names[i] = terminalText(p.String())
		}
		return nil, fmt.Errorf("%w: %s names %s, which is none of the agent's tables; the tables row-level security hides from it are: %s", errUsage, what, strings.Join(names, ", "), tableNames(entries))
	}
	return picked, nil
}

func tableNames(entries []rlspick.Entry) string {
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = terminalText(e.Table)
	}
	return strings.Join(names, ", ")
}

// Exit codes of a killed process: 128 plus the signal.
const (
	exitSigHup  = 129
	exitSigTerm = 143
)

// rlsListExample is the flag form the messages show.
const rlsListExample = "--agent-rls=us.*,global.user_router"

// pipedAnswers prints the tables grouped by schema on stderr and reads one
// line of stdin.
func pipedAnswers(c *cliIO, agent string, own []string, entries []rlspick.Entry) ([]bool, error) {
	fmt.Fprintf(c.stderr, "Row-level security hides every row of these tables from %s:\n", terminalText(agent))
	m := rlspick.New(entries)
	for _, g := range m.Groups() {
		fmt.Fprintf(c.stderr, "  %s\n", g)
	}
	fmt.Fprintf(c.stderr, "Which tables should %s see all rows of? Answer all, none, or a list such as us.*,global.user_router (the --agent-rls form); Enter or end of input is all: ", terminalText(agent))
	line, err := c.line()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	ans, err := rlspick.ParseAnswer(line)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %q as the row-level security answer: answer all, none or a list in the --agent-rls form, for example %s (%w)",
			errUsage, terminalText(line), rlsListExample, err)
	}
	switch {
	case ans.All:
		return fill(make([]bool, len(entries)), true), nil
	case ans.None:
		return make([]bool, len(entries)), nil
	}
	return pickByList(entries, own, ans.Patterns, "the answer")
}

// checklistAnswers runs the checklist on the terminal.
func checklistAnswers(c *cliIO, agent string, asks []rlsAsk, entries []rlspick.Entry) ([]bool, error) {
	name := terminalText(agent)
	header := []string{
		fmt.Sprintf("Row-level security hides every row of these tables from %s.", name),
		fmt.Sprintf("Checked tables get a policy so %s can see all rows.", name),
		"Space toggles, a toggles a whole schema, → and ← open and close one, Enter confirms.",
		"Without a terminal, --agent-rls=all-rows, none or a list answers this.",
	}
	m := rlspick.New(entries)
	if err := runChecklist(c.terminal, c.stdin, c.stderr, m, header); err != nil {
		return nil, err
	}
	checked := map[string]bool{}
	for _, t := range m.Checked() {
		checked[t] = true
	}
	out := make([]bool, len(asks))
	for i, a := range asks {
		out[i] = checked[a.Table]
	}
	return out, nil
}

// runChecklist puts the terminal in raw mode for the checklist and puts it
// back on every way out: Enter, Ctrl-C (a byte in raw mode), the input
// ending, a signal, a failed draw.
func runChecklist(tty *os.File, in io.Reader, out io.Writer, m *rlspick.Model, header []string) error {
	fd := int(tty.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("cannot read keys from the terminal: %w; answer with --agent-rls=all-rows, none or a list such as us.*,global.user_router", err)
	}
	restore := func() {
		_ = term.Restore(fd, old)
		_, _ = io.WriteString(out, "\x1b[?25h")
	}
	defer restore()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	defer func() { signal.Stop(sig); close(done) }()
	go func() {
		select {
		case s := <-sig:
			restore()
			code := exitSigTerm
			if s == syscall.SIGHUP {
				code = exitSigHup
			}
			os.Exit(code)
		case <-done:
		}
	}()
	w, h, err := term.GetSize(fd)
	if err != nil {
		w, h = 0, 0
	}
	err = rlspick.Run(in, out, m, header, w, h)
	if errors.Is(err, rlspick.ErrCanceled) {
		return errors.New("canceled; nothing changed")
	}
	return err
}
