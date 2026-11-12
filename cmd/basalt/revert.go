package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/revert"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// revertFlags are basalt revert's options.
type revertFlags struct {
	change, run, task string
	intent            string
	apply             string
	status            string
	pagesURL          string
	local             string // origin of the engine's local pages, "" when not served
	dryRun, asJSON    bool
	open              bool
}

// runRevert: basalt revert. The person's command (M3): it prepares the
// revert with the agent credential, shows what will be restored and what
// is left alone, prints the revert link, and relays the code the revert
// page gives back. Postgres checks the passkey signature and runs the
// revert; the CLI decides nothing.
func runRevert(c *cliIO, args []string) int {
	fs := c.flags("revert")
	var f revertFlags
	fs.StringVar(&f.change, "change", "", "revert one change (a revert's own change id reverts that revert)")
	fs.StringVar(&f.run, "run", "", "revert every change of one run")
	fs.StringVar(&f.task, "task", "", "revert every change of one task, by any agent")
	fs.StringVar(&f.intent, "intent", "", "why you revert (recorded); default \"Revert <scope> <id>\"")
	fs.StringVar(&f.apply, "apply", "", "apply a prepared revert with the code the revert page gave you")
	fs.StringVar(&f.status, "status", "", "show a revert's progress (a large revert is applied by the agent in batches)")
	pagesURLFlag(fs, &f.pagesURL, "pages base URL (default: the engine config's pagesUrl, else "+links.DefaultLocal+")")
	fs.BoolVar(&f.open, "open", false, "open the revert link in your browser instead of printing it")
	fs.BoolVar(&f.dryRun, "dry-run", false, "only show what the revert would do")
	fs.BoolVar(&f.asJSON, "json", false, "print the lines and the result as JSON")
	agent := fs.String("agent", "", "use this agent's credential from the engine config")
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	credFile := fs.String("credential-file", "", "read the agent's connection string from this file")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	scope, err := f.scope()
	if err != nil {
		return c.fail(err)
	}
	l, err := openLedger(c, *agent, *credFile, *configPath)
	if err != nil {
		return c.fail(err)
	}
	defer l.close()
	if scope.ID != uuid.Nil && !f.dryRun {
		f.local = l.localPages(c, f.pagesURL)
	}
	f.pagesURL = l.pagesBase(f.pagesURL)

	switch {
	case f.status != "":
		return revertStatus(c, l, f.status, f.asJSON)
	case f.apply != "":
		return applyRevertCode(c, l, f.apply, f.asJSON)
	case f.dryRun:
		return previewRevert(c, l, scope, f.asJSON)
	}
	return prepareRevert(c, l, scope, f)
}

// scope is the one scope the flags name; --apply names none.
func (f revertFlags) scope() (guard.RevertScope, error) {
	var named []guard.RevertScope
	for _, s := range []struct {
		kind revert.Scope
		id   string
	}{{revert.ScopeChange, f.change}, {revert.ScopeRun, f.run}, {revert.ScopeTask, f.task}} {
		if s.id == "" {
			continue
		}
		id, err := uuid.Parse(s.id)
		if err != nil {
			return guard.RevertScope{}, fmt.Errorf("%w: --%s must be a uuid", errUsage, strings.ToLower(string(s.kind)))
		}
		named = append(named, guard.RevertScope{Kind: s.kind, ID: id})
	}
	if f.apply != "" || f.status != "" {
		if len(named) > 0 || f.dryRun || f.open || (f.apply != "" && f.status != "") {
			return guard.RevertScope{}, fmt.Errorf("%w: --apply takes only the code, --status only the revert id", errUsage)
		}
		return guard.RevertScope{}, nil
	}
	if f.open && f.dryRun {
		return guard.RevertScope{}, fmt.Errorf("%w: --dry-run makes no link to open", errUsage)
	}
	if len(named) != 1 {
		return guard.RevertScope{}, fmt.Errorf("%w: give exactly one of --change, --run, --task", errUsage)
	}
	return named[0], nil
}

func previewRevert(c *cliIO, l *agentLedger, scope guard.RevertScope, asJSON bool) int {
	texts, err := l.PreviewRevert(c.ctx, scope)
	if err != nil {
		return c.fail(fmt.Errorf("cannot preview the revert: %s", pgDetail(err)))
	}
	if err := printRevertLines(c, texts, asJSON); err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, "basalt: dry run, nothing was reverted")
	return exitOK
}

func prepareRevert(c *cliIO, l *agentLedger, scope guard.RevertScope, f revertFlags) int {
	intent := f.intent
	if intent == "" {
		intent = fmt.Sprintf("Revert %s %s", strings.ToLower(string(scope.Kind)), scope.ID)
	}
	prep, err := l.PrepareRevert(c.ctx, scope, intent)
	if err != nil {
		return c.fail(fmt.Errorf("cannot prepare the revert: %s", pgDetail(err)))
	}
	if prep.Batched {
		printPlanSize(c, prep)
	}
	if err := printRevertLines(c, prep.Lines, f.asJSON); err != nil {
		return c.fail(err)
	}
	keys, err := l.credentials(c.ctx)
	if err != nil {
		return c.fail(err)
	}
	ids := make([]passkey.Bytes, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	link, err := revert.Request{RevertID: prep.RevertID, Binding: prep.BindingText, Lines: prep.Lines, CredentialIDs: ids}.URL(f.pagesURL)
	if err != nil {
		return c.fail(err)
	}
	pages := linkPages{base: f.pagesURL, local: f.local}
	ref := linkRef{setting: "pagesUrl", item: "revert " + prep.RevertID.String(), again: "the same basalt revert command"}
	link = pages.short(c, "reverts", prep.RevertID, prep.BindingText, link)
	expires := prep.ExpiresAt.UTC().Format(timeLayout)
	switch {
	case f.open:
		fmt.Fprintf(c.stderr, "basalt: revert %s expires %s. Check the rows on the revert page and sign with your passkey.\n", prep.RevertID, expires)
		if err := openLink(c, link, c.stderr, ref); err != nil {
			return c.fail(err)
		}
	default:
		fmt.Fprintf(c.stderr, "basalt: revert %s expires %s. Open this link on a device with your passkey, check the rows, and sign:\n",
			prep.RevertID, expires)
		if err := printLink(c, c.stderr, link, ref); err != nil {
			return c.fail(err)
		}
	}
	if f.local != "" {
		return awaitRevert(c, l, prep.RevertID, f.asJSON)
	}
	fmt.Fprint(c.stderr, "Paste the code the revert page showed: ")
	code, err := c.line()
	if err != nil || code == "" {
		return c.fail(fmt.Errorf("no code given; nothing was reverted. Apply later with basalt revert --apply <code> before %s",
			prep.ExpiresAt.UTC().Format("15:04 UTC")))
	}
	return applyRevertCode(c, l, code, f.asJSON)
}

func applyRevertCode(c *cliIO, l *agentLedger, code string, asJSON bool) int {
	resp, err := revert.ParseResponse(code)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if err := checkRevertLocally(c, l, resp); err != nil {
		return c.fail(err)
	}
	out, err := l.ApplyRevert(c.ctx, resp.RevertID, resp.Assertion())
	if err != nil {
		return c.fail(fmt.Errorf("the database refused the revert: %s", pgDetail(err)))
	}
	return printApplied(c, resp.RevertID, out, asJSON)
}

// printApplied says what an applied revert did. A revert the page relayed
// has no change id here; basalt log shows it.
func printApplied(c *cliIO, id uuid.UUID, out guard.AppliedRevert, asJSON bool) int {
	if asJSON {
		return printJSONValue(c, out)
	}
	if out.Batched {
		fmt.Fprintf(c.stderr, "basalt: signed. Your agent restores the %d remaining rows in batches of up to %d (MCP apply_revert_batch) before %s; %d rows are left as they are.\n",
			out.Pending, revert.MaxBatch, out.ApplyBy.UTC().Format(timeLayout), out.Skipped)
		fmt.Fprintf(c.stderr, "basalt: tell your agent: apply revert %s in batches\n", id)
		fmt.Fprintf(c.stderr, "basalt: follow it with: basalt revert --status %s\n", id)
		return exitOK
	}
	change := ""
	if out.ChangeID != uuid.Nil {
		change = fmt.Sprintf(" (change %s)", out.ChangeID)
	}
	fmt.Fprintf(c.stderr, "basalt: reverted: %d rows restored, %d left as they are%s\n", out.Rows, out.Skipped, change)
	return exitOK
}

// revertPoll is how often basalt revert checks whether the page's relay
// applied the revert.
const revertPoll = time.Second

// awaitRevert waits for the revert to be signed on the engine's local page,
// which relays it, while still taking a pasted code (CONTRACT.md, CLI). It
// ends when the revert is applied or signed, or when it expires.
func awaitRevert(c *cliIO, l *agentLedger, id uuid.UUID, asJSON bool) int {
	fmt.Fprintln(c.stderr, "basalt: waiting for your signature on the revert page (or paste the code it shows here)...")
	codes := make(chan string, 1)
	go func() {
		// A closed or empty stdin just leaves the page to finish it.
		if code, err := c.line(); err == nil && code != "" {
			codes <- code
		}
	}()
	tick := time.NewTicker(revertPoll)
	defer tick.Stop()
	for {
		select {
		case code := <-codes:
			return applyRevertCode(c, l, code, asJSON)
		case <-c.ctx.Done():
			return c.fail(c.ctx.Err())
		case <-tick.C:
		}
		r, err := l.FindRevert(c.ctx, id)
		if err != nil {
			return c.fail(err)
		}
		switch {
		case r.Status == ledger.RevertExpired || (r.Status == ledger.RevertPending && !c.now().Before(r.ExpiresAt)):
			return c.fail(errors.New("the revert expired unsigned; nothing was reverted. Run basalt revert again"))
		case r.Status == ledger.RevertPending:
			continue
		}
		return printApplied(c, id, guard.AppliedRevert{
			Rows: r.Rows, Skipped: r.Skipped, Batched: r.Batched, Pending: r.Progress.Pending, ApplyBy: r.ApplyBy,
		}, asJSON)
	}
}

// timeLayout is how the CLI prints a deadline.
const timeLayout = "2006-01-02 15:04 UTC"

// printPlanSize says what a large plan is before its sample lines.
func printPlanSize(c *cliIO, prep guard.PreparedRevert) {
	b, err := revert.ParseBinding(prep.BindingText)
	if err != nil {
		return // PrepareRevert parsed it already
	}
	fmt.Fprintf(c.stderr, "basalt: large revert: %d rows, %d to restore and %d left as they are. You sign it once; your agent then restores it in batches of up to %d within %d hours of your signature.\n",
		b.Lines(), b.Rows, b.Skipped, revert.MaxBatch, int(revert.ApplyWindow.Hours()))
	skips, restores := revert.SampleCounts(b.Skipped, b.Rows)
	fmt.Fprintf(c.stderr, "basalt: below and in the link: %d rows, %d to restore and %d left as they are. The signature covers all %d.\n",
		len(prep.Lines), restores, skips, b.Lines())
}

// revertStatusDTO is basalt revert --status --json.
type revertStatusDTO struct {
	RevertID     string           `json:"revertId"`
	Status       string           `json:"status"`
	Batched      bool             `json:"batched"`
	Lines        int              `json:"lines"`
	Restored     int              `json:"restored"`
	Skipped      int              `json:"skipped"`
	Pending      int              `json:"pending"`
	Batches      int              `json:"batches"`
	ExpiresAt    time.Time        `json:"expiresAt"`
	SignedAt     *time.Time       `json:"signedAt,omitempty"`
	ApplyBy      *time.Time       `json:"applyBy,omitempty"`
	SkippedLines []skippedLineDTO `json:"skippedLines"`
}

type skippedLineDTO struct {
	Line     int         `json:"line"`
	Batch    *int        `json:"batch,omitempty"`
	Conflict string      `json:"conflict"`
	SQLState string      `json:"sqlState,omitempty"`
	Plan     revert.Line `json:"plan"`
}

// revertStatus: basalt revert --status. A revert this agent's role
// prepared: its status, and for a large plan its progress and every line
// skipped so far.
func revertStatus(c *cliIO, l *agentLedger, idText string, asJSON bool) int {
	id, err := uuid.Parse(idText)
	if err != nil {
		return c.fail(fmt.Errorf("%w: --status must be a revert id", errUsage))
	}
	r, err := l.FindRevert(c.ctx, id)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return c.fail(fmt.Errorf("no revert %s prepared with this agent's credential", id))
	}
	if err != nil {
		return c.fail(err)
	}
	out := revertStatusDTO{
		RevertID: r.ID.String(), Status: r.Status, Batched: r.Batched, Lines: r.Rows + r.Skipped,
		Restored: r.Progress.Restored, Skipped: r.Progress.Skipped, Pending: r.Progress.Pending, Batches: r.Batches,
		ExpiresAt: r.ExpiresAt, SignedAt: r.SignedAt, ApplyBy: r.ApplyBy, SkippedLines: []skippedLineDTO{},
	}
	if !r.Batched && r.Status == ledger.RevertApplied {
		out.Restored, out.Skipped = r.Rows, r.Skipped
	}
	if r.Batched {
		if out.SkippedLines, err = skippedLines(c, l, id); err != nil {
			return c.fail(err)
		}
	}
	if asJSON {
		return printJSONValue(c, out)
	}
	printRevertStatus(c, out)
	return exitOK
}

// skippedLines reads every line of a plan skipped so far, page by page.
func skippedLines(c *cliIO, l *agentLedger, id uuid.UUID) ([]skippedLineDTO, error) {
	out := []skippedLineDTO{}
	p := ledger.RevertLineParams{Params: pagination.Params{Limit: pagination.MaxLimit}, RevertID: id, Outcome: ledger.OutcomeSkipped}
	for {
		page, err := l.ListRevertLines(c.ctx, p)
		if err != nil {
			return nil, err
		}
		for _, l := range page.Items {
			parsed, err := revert.ParseLine(l.Text)
			if err != nil {
				return nil, err
			}
			out = append(out, skippedLineDTO{Line: l.No, Batch: l.Batch, Conflict: l.Conflict, SQLState: l.SQLState, Plan: parsed})
		}
		if page.NextCursor == "" {
			return out, nil
		}
		p.Cursor = page.NextCursor
	}
}

func printRevertStatus(c *cliIO, s revertStatusDTO) {
	fmt.Fprintf(c.stdout, "revert %s: %s\n", s.RevertID, s.Status)
	if !s.Batched {
		fmt.Fprintf(c.stdout, "  %d rows, applied in one call by basalt revert; sign by %s\n", s.Lines, s.ExpiresAt.UTC().Format(timeLayout))
		if s.Status == ledger.RevertApplied {
			fmt.Fprintf(c.stdout, "  %d restored, %d left as they are\n", s.Restored, s.Skipped)
		}
		return
	}
	fmt.Fprintf(c.stdout, "  %d rows: %d restored, %d left as they are, %d pending, in %d batches\n",
		s.Lines, s.Restored, s.Skipped, s.Pending, s.Batches)
	switch {
	case s.ApplyBy != nil:
		fmt.Fprintf(c.stdout, "  signed %s; the agent must finish by %s\n", s.SignedAt.UTC().Format(timeLayout), s.ApplyBy.UTC().Format(timeLayout))
	default:
		fmt.Fprintf(c.stdout, "  not signed yet; sign by %s\n", s.ExpiresAt.UTC().Format(timeLayout))
	}
	skipped := make([]revert.Line, 0, len(s.SkippedLines))
	for _, l := range s.SkippedLines {
		skipped = append(skipped, withConflict(l.Plan, l.Conflict, l.SQLState))
	}
	for _, l := range displayOrder(skipped) {
		fmt.Fprintln(c.stdout, revertLineText(l))
	}
}

// withConflict is a plan line as it ended: skipped for the reason found at
// the signature or when its batch ran (people win).
func withConflict(l revert.Line, conflict, sqlState string) revert.Line {
	l.Action = revert.ActionSkip
	l.Conflict = &conflict
	l.SQLState = nil
	if sqlState != "" {
		l.SQLState = &sqlState
	}
	return l
}

// checkRevertLocally verifies the code with the Go mirror of the Postgres
// check when this role prepared the revert, for a clear message before
// relaying. Postgres checks again either way.
func checkRevertLocally(c *cliIO, l *agentLedger, resp revert.Response) error {
	r, err := l.FindRevert(c.ctx, resp.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return nil // prepared by another role: only Postgres can check it
	}
	return verifyCode(c, l, err, resp.CredentialID, "reverted", func(k passkey.Credential) error {
		_, err := revert.Verify(r.BindingText, k, resp)
		return err
	})
}

// printRevertLines prints every line in reading order (displayOrder): what
// is restored, then what is left alone and why. --json keeps the signed
// order.
func printRevertLines(c *cliIO, texts []string, asJSON bool) error {
	lines := make([]revert.Line, 0, len(texts))
	for _, t := range texts {
		l, err := revert.ParseLine(t)
		if err != nil {
			return err
		}
		lines = append(lines, l)
	}
	if asJSON {
		if code := printJSONValue(c, lines); code != exitOK {
			return errors.New("cannot print the lines")
		}
		return nil
	}
	restored := 0
	for _, l := range displayOrder(lines) {
		if l.Action == revert.ActionRestore {
			restored++
		}
		fmt.Fprintln(c.stdout, revertLineText(l))
	}
	fmt.Fprintf(c.stderr, "basalt: %d rows to restore, %d left as they are (people win)\n", restored, len(lines)-restored)
	return nil
}

// revertLineText is one line for a person: action, table, key, and the
// columns that change back (or the reason the row is skipped), with the
// characters that hide or reorder text shown as escapes (visibleText).
func revertLineText(l revert.Line) string {
	return visibleText(revertLine(l))
}

func revertLine(l revert.Line) string {
	verb := map[string]string{"UPDATE": "restore", "INSERT": "re-insert", "DELETE": "delete"}[l.Op]
	key := string(l.Key)
	if l.Redacted {
		key = "(values hidden: you cannot read this table)"
	}
	if l.Action == revert.ActionSkip {
		reason := *l.Conflict
		if l.SQLState != nil {
			reason += " " + *l.SQLState
		}
		return fmt.Sprintf("skip       %s %s: %s", l.Table, key, reason)
	}
	head := fmt.Sprintf("%-10s %s %s", verb, l.Table, key)
	changes := changedColumns(l.Now, l.Set)
	if l.Op != "UPDATE" || len(changes) == 0 {
		return head
	}
	return head + ": " + strings.Join(changes, ", ")
}

// changedColumns lists "col: now -> restored" for the columns that differ.
func changedColumns(now, set json.RawMessage) []string {
	var before, after map[string]json.RawMessage
	if json.Unmarshal(now, &before) != nil || json.Unmarshal(set, &after) != nil {
		return nil
	}
	out := make([]string, 0, len(after))
	for col, v := range after {
		if !bytes.Equal(before[col], v) {
			out = append(out, fmt.Sprintf("%s: %s -> %s", col, before[col], v))
		}
	}
	sort.Strings(out)
	return out
}

func printJSONValue(c *cliIO, v any) int {
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return c.fail(err)
	}
	return exitOK
}
