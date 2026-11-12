package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// runLog: basalt log. Reads the agent's change records with the agent's
// own credential (D6) and warns about the chain, unguarded tables and a
// silent engine.
func runLog(c *cliIO, args []string) int {
	fs := c.flags("log")
	runFlag := fs.String("run", "", "only this run, with the rows each change wrote")
	limit := fs.Int("limit", pagination.DefaultLimit, fmt.Sprintf("page size (max %d)", pagination.MaxLimit))
	cursor := fs.String("cursor", "", "next-page cursor printed by the previous call")
	sortFlag := fs.String("sort", ledger.ChangeSortSpec.Default, "id (oldest first) or -id (newest first)")
	asJSON := fs.Bool("json", false, "print change records as JSON")
	agent := fs.String("agent", "", "read this agent's credential from the engine config")
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	credFile := fs.String("credential-file", "", "read the agent's connection string from this file")
	fullCheck := fs.Bool("full-check", false, "recompute the whole ledger chain instead of checking from the last verified head")
	full := fs.Bool("full", false, "print whole before and after rows and every read, instead of the compact view")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	params := ledger.ChangeListParams{Params: pagination.Params{Limit: *limit, Cursor: *cursor, Sort: *sortFlag}}
	if _, err := params.ParseSort(ledger.ChangeSortSpec); err != nil || *sortFlag == "" {
		return c.fail(fmt.Errorf("%w: --sort must be id or -id, got %q", errUsage, *sortFlag))
	}
	params.ApplyDefaultsAndClamp()
	if *runFlag != "" {
		id, err := uuid.Parse(*runFlag)
		if err != nil {
			return c.fail(fmt.Errorf("%w: --run must be a uuid", errUsage))
		}
		params.RunID = id
	}
	dsn, err := agentURL(c, *agent, *credFile, *configPath)
	if err != nil {
		return c.fail(err)
	}

	ctx := c.ctx
	conn, err := connect(ctx, dsn)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(ctx)

	health, err := checkHealth(c, conn, *fullCheck)
	if err != nil {
		return c.fail(err)
	}
	page, err := ledger.ListChanges(ctx, conn, params)
	if err != nil {
		return c.fail(err)
	}
	var rowsByChange map[uuid.UUID][]ledger.RowChange
	if params.RunID != uuid.Nil || *asJSON {
		ids := make([]uuid.UUID, 0, len(page.Items))
		for _, ch := range page.Items {
			ids = append(ids, ch.ID)
		}
		if rowsByChange, err = ledger.RowChanges(ctx, conn, ids); err != nil {
			return c.fail(err)
		}
	}

	keys, err := ledger.ListPasskeys(ctx, conn)
	if err != nil {
		return c.fail(err)
	}

	warn(c, health)
	warnPasskeys(c, keys)
	if *asJSON {
		if err := printJSON(c, page.Items, rowsByChange); err != nil {
			return c.fail(err)
		}
	} else {
		printText(c, page.Items, rowsByChange, *full)
	}
	if page.NextCursor != "" {
		fmt.Fprintf(c.stderr, "next cursor: %s\n", page.NextCursor)
	}
	return exitOK
}

// agentURL finds the agent's connection string: --credential-file, then
// the credential file of --agent in the engine config, then
// BASALT_DATABASE_URL. A flag always wins over the environment. A
// credential file readable by group or others is refused.
func agentURL(c *cliIO, agent, credFile, configPath string) (string, error) {
	if credFile != "" {
		return config.ReadCredential(credFile)
	}
	if agent != "" {
		return agentConfigURL(agent, configPath)
	}
	if v := c.getenv(envAgentURL); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%w: give --agent, --credential-file or %s", errUsage, envAgentURL)
}

// agentConfigURL reads the credential file the engine config names for agent.
func agentConfigURL(agent, configPath string) (string, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", err
	}
	for _, a := range cfg.Agents {
		if a.Name == agent {
			return config.ReadCredential(a.CredentialFile)
		}
	}
	return "", fmt.Errorf("agent %q is not in %s; run basalt init --agent %s", agent, configPath, agent)
}

// checkHealth verifies the chain from the head this user last verified on
// this database and role (kept under the user cache directory), and pins
// the new head when it is intact. A pin that cannot be read or written
// only costs a full check, with a warning.
func checkHealth(c *cliIO, conn *pgx.Conn, full bool) (ledger.Health, error) {
	pins, name, err := logPins(c, conn.Config())
	if err != nil {
		fmt.Fprintf(c.stderr, "warning: no ledger pin, checking the whole chain: %v\n", err)
		return ledger.CheckHealth(c.ctx, conn, c.now(), ledger.HealthOptions{Full: true})
	}
	opts := ledger.HealthOptions{Full: full}
	pin, ok, err := pins.Load(name)
	if err != nil {
		fmt.Fprintf(c.stderr, "warning: ledger pin unreadable, checking the whole chain: %v\n", err)
	}
	if ok {
		opts.Pin = &pin
	}
	h, err := ledger.CheckHealth(c.ctx, conn, c.now(), opts)
	if err != nil || !h.Chain.Intact {
		return h, err
	}
	if err := pins.Save(name, h.Head); err != nil {
		fmt.Fprintf(c.stderr, "warning: could not save the ledger pin: %v\n", err)
	}
	return h, nil
}

// logPins is where basalt log keeps its pins: $BASALT_CACHE_DIR or the
// user cache directory, one file per database and role.
func logPins(c *cliIO, cfg *pgx.ConnConfig) (chainpin.File, string, error) {
	dir := c.getenv(envCacheDir)
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return chainpin.File{}, "", err
		}
		dir = filepath.Join(base, "basalt")
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d\x00%s\x00%s", cfg.Host, cfg.Port, cfg.Database, cfg.User))
	return chainpin.File{Dir: filepath.Join(dir, "ledger-pins")}, hex.EncodeToString(sum[:pinNameBytes]), nil
}

// pinNameBytes of the sha256 name a pin file (hex encoded).
const pinNameBytes = 16

func warn(c *cliIO, h ledger.Health) {
	if !h.Chain.Intact {
		fmt.Fprintf(c.stderr, "warning: ledger chain broken at seq %d; ledger rows were changed or removed outside basalt\n", h.Chain.BrokenAt)
	}
	if h.DeadMan != nil {
		fmt.Fprintf(c.stderr, "warning: the engine was silent for %d hours (last heartbeat %s) until %s (dead-man row)\n",
			h.DeadMan.SilentHours, h.DeadMan.LastHeartbeat, h.DeadMan.At.UTC().Format(time.RFC3339))
	}
	for _, u := range h.Uncovered {
		fmt.Fprintf(c.stderr, "warning: table %s is not guarded (%s); run basalt init again\n", u.Table, u.Why)
	}
	for _, t := range h.RLSBlind {
		fmt.Fprintf(c.stderr, "warning: row-level security is on for %s and no policy lets this agent see rows; it reads 0 rows there\n", t)
	}
	if h.HeartbeatStale {
		fmt.Fprintf(c.stderr, "warning: no engine heartbeat since %s; the engine may have stopped\n",
			h.LastHeartbeat.UTC().Format(time.RFC3339))
	}
}

// warnPasskeys warns when no passkey is active, and names each passkey
// that signed nothing for ledger.PasskeyUnusedAfter: WebAuthn never says a
// passkey was deleted, so a lost one shows only as silence.
func warnPasskeys(c *cliIO, keys []ledger.Passkey) {
	if len(keys) == 0 {
		fmt.Fprintln(c.stderr, "warning: no active passkey; held writes and reverts cannot be signed until basalt init --add-passkey")
		return
	}
	now := c.now()
	for _, k := range keys {
		if !k.Unused(now) {
			continue
		}
		id := passkey.Bytes(k.Credential.ID).String()
		fmt.Fprintf(c.stderr, "warning: passkey %q (%s) has not signed anything for %d days or more (last used %s); if it is lost, run basalt passkey check or basalt passkey remove %s\n",
			k.Label, id, int(ledger.PasskeyUnusedAfter.Hours()/hoursPerDay), lastUsed(k.LastUsedAt), id)
	}
}

// hoursPerDay converts durations to days for messages.
const hoursPerDay = 24

// printText prints one line per change, newest first, with the rows it
// wrote below it when they were loaded (--run). Compact by default: a row
// shows its key and the columns that changed, and consecutive reads
// collapse into one line. full prints whole rows and every read.
func printText(c *cliIO, changes []ledger.Change, rows map[uuid.UUID][]ledger.RowChange, full bool) {
	for i := 0; i < len(changes); i++ {
		ch := changes[i]
		if n := readRun(changes[i:]); !full && n > 1 {
			fmt.Fprintln(c.stdout, readsLine(changes[i:i+n]))
			i += n - 1
			continue
		}
		fmt.Fprintln(c.stdout, changeLine(ch))
		if ch.Code != "" {
			fmt.Fprintf(c.stdout, "    refused: %s %s\n", ch.Code, ch.Reason)
		}
		for _, r := range rows[ch.ID] {
			fmt.Fprintf(c.stdout, "    %s\n", rowLine(r, full))
		}
	}
}

func changeLine(ch ledger.Change) string {
	duration := "-"
	if ch.DurationMs != nil {
		duration = fmt.Sprintf("%dms", *ch.DurationMs)
	}
	return fmt.Sprintf("%s  %-8s %-6s %-24s %3d rows  %6s  %s  %q",
		ch.At.UTC().Format(time.RFC3339), ch.Status, ch.Op, ch.Table, ch.Rows, duration, ch.ID, ch.Intent)
}

// opSelect is the op of a read's change record (M1.5).
const opSelect = "SELECT"

func isRead(ch ledger.Change) bool { return ch.Op == opSelect && ch.Code == "" }

// readRun is how many changes from the first are consecutive reads.
func readRun(changes []ledger.Change) int {
	n := 0
	for n < len(changes) && isRead(changes[n]) {
		n++
	}
	return n
}

// readsLine is consecutive reads in one line: how many, the rows they
// returned, and their tables in first-seen order with a count each.
func readsLine(reads []ledger.Change) string {
	rows := 0
	var tables []string
	perTable := map[string]int{}
	for _, r := range reads {
		rows += r.Rows
		t := r.Table
		if t == "" {
			t = "(no table)"
		}
		if perTable[t] == 0 {
			tables = append(tables, t)
		}
		perTable[t]++
	}
	parts := make([]string, 0, len(tables))
	for _, t := range tables {
		parts = append(parts, fmt.Sprintf("%s (%d)", t, perTable[t]))
	}
	return fmt.Sprintf("%s  %-8s %-6s %d reads, %d rows: %s",
		reads[0].At.UTC().Format(time.RFC3339), reads[0].Status, opSelect, len(reads), rows, strings.Join(parts, ", "))
}

// rowLine is one row a change wrote: compact (key, and for an update the
// columns that changed) or full (whole before and after rows).
func rowLine(r ledger.RowChange, full bool) string {
	prefix := r.Op + " " + r.Table
	if r.Cascaded {
		prefix += " (cascaded)"
	}
	switch {
	case r.BasedOn != nil:
		prefix += " (read at " + r.BasedOn.Version + ")"
	case r.BlindWrite:
		prefix += " (blind write)"
	}
	switch {
	case r.Redacted:
		return prefix + " values hidden: the agent cannot read this table"
	case r.Pruned:
		return prefix + " " + compactJSON(r.Key) + " values pruned after 30 days"
	case full:
		return prefix + " " + compactJSON(r.Key) + " before=" + compactJSON(r.Before) + " after=" + compactJSON(r.After)
	}
	line := prefix + " " + compactJSON(r.Key)
	if changed := changedValues(r.Before, r.After); r.Op == "UPDATE" && len(changed) > 0 {
		line += " " + strings.Join(changed, ", ")
	}
	return line
}

// changedValues lists "col old -> new" for the columns whose values
// differ, by column name.
func changedValues(before, after map[string]any) []string {
	cols := make([]string, 0, len(after))
	for col, v := range after {
		if old, ok := before[col]; !ok || !reflect.DeepEqual(old, v) {
			cols = append(cols, col)
		}
	}
	sort.Strings(cols)
	out := make([]string, 0, len(cols))
	for _, col := range cols {
		out = append(out, col+" "+displayValue(before[col])+" -> "+displayValue(after[col]))
	}
	return out
}

// bareValue is a string printed without quotes: a word that cannot be
// mistaken for a number, a boolean or null.
var bareValue = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.:@/+-]*$`)

// displayValue is a value for a person: a plain word bare, anything else
// as JSON.
func displayValue(v any) string {
	if s, ok := v.(string); ok && bareValue.MatchString(s) && s != "null" && s != "true" && s != "false" {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}

func compactJSON(v map[string]any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}

func printJSON(c *cliIO, changes []ledger.Change, rows map[uuid.UUID][]ledger.RowChange) error {
	out := make([]ledger.Record, 0, len(changes))
	for _, ch := range changes {
		out = append(out, ledger.RecordFromDomain(ch, rows[ch.ID]))
	}
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
