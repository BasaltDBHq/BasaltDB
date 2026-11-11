package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
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
	page              string
	dryRun, asJSON    bool
}

// prepareTimeout replaces the agent role's statement timeout while
// prepare_revert runs: the trial of a large plan can take minutes.
const prepareTimeout = 10 * time.Minute

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
	fs.StringVar(&f.page, "page", revert.PageURL, "revert page")
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
	dsn, err := agentURL(c, *agent, *credFile, *configPath)
	if err != nil {
		return c.fail(err)
	}
	conn, err := connect(c.ctx, dsn)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)

	switch {
	case f.status != "":
		return revertStatus(c, conn, f.status, f.asJSON)
	case f.apply != "":
		return applyRevertCode(c, conn, f.apply, f.asJSON)
	case f.dryRun:
		return previewRevert(c, conn, scope, f.asJSON)
	}
	return prepareRevert(c, conn, scope, f)
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
		if len(named) > 0 || f.dryRun || (f.apply != "" && f.status != "") {
			return guard.RevertScope{}, fmt.Errorf("%w: --apply takes only the code, --status only the revert id", errUsage)
		}
		return guard.RevertScope{}, nil
	}
	if len(named) != 1 {
		return guard.RevertScope{}, fmt.Errorf("%w: give exactly one of --change, --run, --task", errUsage)
	}
	return named[0], nil
}

func previewRevert(c *cliIO, conn *pgx.Conn, scope guard.RevertScope, asJSON bool) int {
	texts, err := guard.PreviewRevert(c.ctx, conn, scope)
	if err != nil {
		return c.fail(fmt.Errorf("cannot preview the revert: %s", pgDetail(err)))
	}
	if err := printRevertLines(c, texts, asJSON); err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, "basalt: dry run, nothing was reverted")
	return exitOK
}

func prepareRevert(c *cliIO, conn *pgx.Conn, scope guard.RevertScope, f revertFlags) int {
	intent := f.intent
	if intent == "" {
		intent = fmt.Sprintf("Revert %s %s", strings.ToLower(string(scope.Kind)), scope.ID)
	}
	var prep guard.PreparedRevert
	err := pgx.BeginFunc(c.ctx, conn, func(tx pgx.Tx) error {
		// Plain SQL: a transaction-local setting.
		if _, err := tx.Exec(c.ctx, `SELECT pg_catalog.set_config('statement_timeout', $1, true)`,
			strconv.FormatInt(prepareTimeout.Milliseconds(), 10)); err != nil {
			return err
		}
		var err error
		prep, err = guard.PrepareRevert(c.ctx, tx, scope, intent)
		return err
	})
	if err != nil {
		return c.fail(fmt.Errorf("cannot prepare the revert: %s", pgDetail(err)))
	}
	if prep.Batched {
		printPlanSize(c, prep)
	}
	if err := printRevertLines(c, prep.Lines, f.asJSON); err != nil {
		return c.fail(err)
	}
	keys, err := ledger.Passkeys(c.ctx, conn)
	if err != nil {
		return c.fail(err)
	}
	ids := make([]passkey.Bytes, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	link, err := revert.Request{RevertID: prep.RevertID, Binding: prep.BindingText, Lines: prep.Lines, CredentialIDs: ids}.URL(f.page)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stderr, "basalt: revert %s expires %s. Open this link on a device with your passkey, check the rows, and sign:\n",
		prep.RevertID, prep.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintln(c.stderr, link)
	fmt.Fprint(c.stderr, "Paste the code the revert page showed: ")
	code, err := c.line()
	if err != nil || code == "" {
		return c.fail(fmt.Errorf("no code given; nothing was reverted. Apply later with basalt revert --apply <code> before %s",
			prep.ExpiresAt.UTC().Format("15:04 UTC")))
	}
	return applyRevertCode(c, conn, code, f.asJSON)
}

func applyRevertCode(c *cliIO, conn *pgx.Conn, code string, asJSON bool) int {
	resp, err := revert.ParseResponse(code)
	if err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if err := checkRevertLocally(c, conn, resp); err != nil {
		return c.fail(err)
	}
	out, err := guard.ApplyRevert(c.ctx, conn, resp.RevertID, resp.Assertion())
	if err != nil {
		return c.fail(fmt.Errorf("the database refused the revert: %s", pgDetail(err)))
	}
	if asJSON {
		return printJSONValue(c, out)
	}
	if out.Batched {
		fmt.Fprintf(c.stderr, "basalt: signed. Your agent restores the %d remaining rows in batches of up to %d (MCP apply_revert_batch) before %s; %d rows are left as they are.\n",
			out.Pending, revert.MaxBatch, out.ApplyBy.UTC().Format(timeLayout), out.Skipped)
		fmt.Fprintf(c.stderr, "basalt: follow it with: basalt revert --status %s\n", resp.RevertID)
		return exitOK
	}
	fmt.Fprintf(c.stderr, "basalt: reverted: %d rows restored, %d left as they are (change %s)\n", out.Rows, out.Skipped, out.ChangeID)
	return exitOK
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
	fmt.Fprintf(c.stderr, "basalt: below and in the link: the first %d rows, rows left alone first. The signature covers all %d.\n",
		len(prep.Lines), b.Lines())
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
func revertStatus(c *cliIO, conn *pgx.Conn, idText string, asJSON bool) int {
	id, err := uuid.Parse(idText)
	if err != nil {
		return c.fail(fmt.Errorf("%w: --status must be a revert id", errUsage))
	}
	r, err := ledger.FindRevert(c.ctx, conn, id)
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
		if out.SkippedLines, err = skippedLines(c, conn, id); err != nil {
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
func skippedLines(c *cliIO, conn *pgx.Conn, id uuid.UUID) ([]skippedLineDTO, error) {
	out := []skippedLineDTO{}
	p := ledger.RevertLineParams{Params: pagination.Params{Limit: pagination.MaxLimit}, RevertID: id, Outcome: ledger.OutcomeSkipped}
	for {
		page, err := ledger.ListRevertLines(c.ctx, conn, p)
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
	for _, l := range s.SkippedLines {
		fmt.Fprintln(c.stdout, revertLineText(withConflict(l.Plan, l.Conflict, l.SQLState)))
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
func checkRevertLocally(c *cliIO, conn *pgx.Conn, resp revert.Response) error {
	r, err := ledger.FindRevert(c.ctx, conn, resp.RevertID)
	if errors.Is(err, ledger.ErrRevertNotFound) {
		return nil // prepared by another role: only Postgres can check it
	}
	return verifyCode(c, conn, err, resp.CredentialID, "reverted", func(k passkey.Credential) error {
		_, err := revert.Verify(r.BindingText, k, resp)
		return err
	})
}

// printRevertLines prints every line: what is restored, then what is left
// alone and why.
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
	for _, l := range lines {
		if l.Action == revert.ActionRestore {
			restored++
			fmt.Fprintln(c.stdout, revertLineText(l))
		}
	}
	for _, l := range lines {
		if l.Action == revert.ActionSkip {
			fmt.Fprintln(c.stdout, revertLineText(l))
		}
	}
	fmt.Fprintf(c.stderr, "basalt: %d rows to restore, %d left as they are (people win)\n", restored, len(lines)-restored)
	return nil
}

// revertLineText is one line for a person: action, table, key, and the
// columns that change back (or the reason the row is skipped).
func revertLineText(l revert.Line) string {
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
