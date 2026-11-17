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

	"github.com/basaltdbhq/basaltdb/internal/chainpin"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/largevalue"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pii"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
	"github.com/basaltdbhq/basaltdb/pkg/wiretime"
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
	*configPath = configOrFallback(c.host, fs, *configPath)
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
	l, err := openLedger(c, *agent, *credFile, *configPath)
	if err != nil {
		return c.fail(err)
	}
	defer l.close()

	ctx := c.ctx
	health, err := checkHealth(c, l, *fullCheck)
	if err != nil {
		return c.fail(err)
	}
	page, err := l.ListChanges(ctx, params)
	if err != nil {
		return c.fail(err)
	}
	var rowsByChange map[uuid.UUID][]ledger.RowChange
	if params.RunID != uuid.Nil || *asJSON {
		ids := make([]uuid.UUID, 0, len(page.Items))
		for _, ch := range page.Items {
			ids = append(ids, ch.ID)
		}
		if rowsByChange, err = l.RowChanges(ctx, ids); err != nil {
			return c.fail(err)
		}
	}

	keys, err := l.ListPasskeys(ctx)
	if err != nil {
		return c.fail(err)
	}

	printPII(c, health.PII, l.configPath)
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
// credential file readable by group or others is refused. As root, the
// files are read without following links (loadEngineConfig).
func agentURL(c *cliIO, agent, credFile, configPath string) (string, error) {
	if credFile != "" {
		return readCredentialFlag(c, credFile)
	}
	if agent != "" {
		return agentConfigURL(c, agent, configPath)
	}
	if v := c.getenv(envAgentURL); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%w: give --agent, --credential-file or %s", errUsage, envAgentURL)
}

// agentConfigURL reads the credential file the engine config names for agent.
func agentConfigURL(c *cliIO, agent, configPath string) (string, error) {
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return "", err
	}
	for _, a := range cfg.Agents {
		if a.Name == agent {
			return cfg.credential(a.CredentialFile)
		}
	}
	return "", errAgentNotInConfig(agent, configPath)
}

// checkHealth verifies the chain from the head this user last verified on
// this database and role (kept under the user cache directory), and pins
// the new head when it is intact. A pin that cannot be read or written
// only costs a full check, with a warning.
func checkHealth(c *cliIO, l *agentLedger, full bool) (ledger.Health, error) {
	pins, name, err := logPins(c, l.pinKey)
	if err != nil {
		fmt.Fprintf(c.stderr, "warning: no ledger pin, checking the whole chain: %v\n", err)
		return l.CheckHealth(c.ctx, ledger.HealthOptions{Full: true})
	}
	opts := ledger.HealthOptions{Full: full}
	pin, ok, err := pins.Load(name)
	if err != nil {
		fmt.Fprintf(c.stderr, "warning: ledger pin unreadable, checking the whole chain: %v\n", err)
	}
	if ok {
		opts.Pin, opts.PinInstall = &pin.Head, pin.Install
	}
	opts.SetAside = pin.SetAside
	h, err := l.CheckHealth(c.ctx, opts)
	if err != nil {
		return h, err
	}
	switch {
	case h.PinMoved:
		fprintSafef(c.stderr, "warning: the guard's schema was dropped and restored with the same ledger (guard install %d is now %d); the ledger pin moved to the new install\n",
			pin.Install, h.Install)
	case h.PinSetAside:
		pin = pin.Kept(guard.SetAside{
			PinnedSeq: pin.Head.Seq, PinnedHash: pin.Head.Hash, PinnedInstall: pin.Install, Install: h.Install, At: c.now().UTC(),
		})
	}
	next := chainpin.Pin{Head: h.Head, Install: h.Install, SetAside: pin.SetAside}
	if !h.Chain.Intact {
		if !h.PinSetAside {
			return h, nil
		}
		// Keep the old pin with the copy of what was reported: the next run
		// reports it again (already recorded) and checks the new chain.
		next = pin
	}
	if err := pins.Save(name, next); err != nil {
		fmt.Fprintf(c.stderr, "warning: could not save the ledger pin: %v\n", err)
	}
	return h, nil
}

// logPins is where basalt log keeps its pins: $BASALT_CACHE_DIR or the
// user cache directory, one file per database and role.
func logPins(c *cliIO, key string) (chainpin.File, string, error) {
	dir := c.getenv(envCacheDir)
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return chainpin.File{}, "", err
		}
		dir = filepath.Join(base, "basalt")
	}
	sum := sha256.Sum256([]byte(key))
	return chainpin.File{Dir: filepath.Join(dir, "ledger-pins")}, hex.EncodeToString(sum[:pinNameBytes]), nil
}

// pinNameBytes of the sha256 name a pin file (hex encoded).
const pinNameBytes = 16

func warn(c *cliIO, h ledger.Health) {
	for _, line := range ledger.ReinstallNotices(h.Reinstalls) {
		fprintSafef(c.stderr, "%s\n", line)
	}
	if !h.Chain.Intact {
		fprintSafef(c.stderr, "warning: ledger chain broken at seq %d; ledger rows were changed or removed outside basalt\n", h.Chain.BrokenAt)
	}
	if h.DeadMan != nil {
		fprintSafef(c.stderr, "warning: the engine was silent for %d hours (last heartbeat %s) until %s (dead-man row)\n",
			h.DeadMan.SilentHours, h.DeadMan.LastHeartbeat, h.DeadMan.At.UTC().Format(time.RFC3339))
	}
	for _, u := range h.Uncovered {
		fprintSafef(c.stderr, "warning: table %s is not guarded (%s); run basalt init again\n", u.Table, u.Why)
	}
	for _, t := range h.RLSBlind {
		fprintSafef(c.stderr, "warning: row-level security is on for %s and no policy lets this agent see rows; it reads 0 rows there\n", t)
	}
	if h.HeartbeatStale {
		fprintSafef(c.stderr, "warning: no engine heartbeat since %s; the engine may have stopped\n",
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

// printPII prints the PII line on stderr and warns about unclassified
// columns and columns that need a review (CONTRACT.md, PII classification,
// basalt log). Nothing before guard version 15 (p nil). The dictionary
// counts come from the engine (service mode) or its status.json; when
// neither is there the line says the dictionary is not built yet.
func printPII(c *cliIO, p *ledger.PIIHealth, configPath string) {
	if p == nil {
		return
	}
	dict := p.Dictionary
	if dict == nil {
		dict = statusDictionary(c, configPath)
	}
	tail := "dictionary not built yet"
	if dict != nil && dict.LastScanAt != nil {
		tail = fmt.Sprintf("dictionary of %d values, last scan %s", dict.Values, dict.LastScanAt.UTC().Format(time.RFC3339))
	}
	fprintSafef(c.stderr, "PII: %d columns classified, %d unclassified; %s\n", p.Classified, p.Unclassified, tail)
	if p.Unclassified > 0 {
		fprintSafef(c.stderr, "basalt: warning: %d columns the agent can read are not classified yet: %s; run basalt classify\n",
			p.Unclassified, piiNames(p.UnclassifiedNames, p.Unclassified))
	}
	if p.Review > 0 {
		fprintSafef(c.stderr, "basalt: warning: %d columns need a classification review (type changed or flagged): %s; run basalt classify\n",
			p.Review, piiNames(p.ReviewNames, p.Review))
	}
}

// piiNames lists at most ledger.MaxPIINames names, then "…" when there are
// more.
func piiNames(names []string, total int) string {
	names = names[:min(len(names), ledger.MaxPIINames)]
	out := strings.Join(names, ", ")
	if total > len(names) {
		out += ", …"
	}
	return out
}

// statusDictionary reads the engine's status.json from the state directory
// the config names (the platform default when the config cannot be read),
// the config read as loadEngineConfig does (hardened as root);
// nil when it cannot be read.
func statusDictionary(c *cliIO, configPath string) *ledger.DictionaryHealth {
	dir := config.DefaultStateDir(runtime.GOOS)
	if cfg, err := loadEngineConfig(c, configPath); err == nil {
		dir = cfg.StateDirFor(runtime.GOOS)
	}
	st, ok := pii.ReadStatus(dir)
	if !ok {
		return nil
	}
	return &ledger.DictionaryHealth{Values: st.DictionaryValues + uint64(st.DeltaValues), LastScanAt: st.LastScanAt}
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
			printLine(c.stdout, readsLine(changes[i:i+n]))
			i += n - 1
			continue
		}
		printLine(c.stdout, changeLine(ch))
		if ch.Code != "" {
			printLine(c.stdout, "    refused: "+ch.Code+" "+ch.Reason)
		}
		for _, r := range rows[ch.ID] {
			printLine(c.stdout, "    "+rowLine(r, full))
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
	r.Key, r.Before, r.After = wiretime.Map(r.Key), wiretime.Map(r.Before), wiretime.Map(r.After)
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
		return prefix + " " + markedJSON(r.Key, r.Marks.Key) + " before=" + markedJSON(r.Before, r.Marks.Before) + " after=" + markedJSON(r.After, r.Marks.After)
	}
	line := prefix + " " + markedJSON(r.Key, r.Marks.Key)
	if changed := changedValues(r.Before, r.After, r.Marks); r.Op == "UPDATE" && len(changed) > 0 {
		line += " " + strings.Join(changed, ", ")
	}
	return line
}

// changedValues lists "col old -> new" for the columns whose values
// differ, by column name.
func changedValues(before, after map[string]any, marks largevalue.Marks) []string {
	cols := make([]string, 0, len(after))
	for col, v := range after {
		if old, ok := before[col]; !ok || !reflect.DeepEqual(old, v) {
			cols = append(cols, col)
		}
	}
	sort.Strings(cols)
	out := make([]string, 0, len(cols))
	for _, col := range cols {
		out = append(out, col+" "+withMark(displayValue(before[col]), marks.Before[col])+" -> "+withMark(displayValue(after[col]), marks.After[col]))
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

// withMark is a printed value followed by the summary of its size and
// sha256 when it is over 1 MiB (largevalue.Summary), "" for any other.
func withMark(text, mark string) string {
	if mark == "" {
		return text
	}
	return text + " " + mark
}

// markedJSON is compactJSON with each large value followed by its
// summary, inside the object, the way the person reads it beside the
// agent's marker. With no large value it is compactJSON.
func markedJSON(v map[string]any, marks map[string]string) string {
	if len(marks) == 0 || v == nil {
		return compactJSON(v)
	}
	cols := make([]string, 0, len(v))
	for col := range v {
		cols = append(cols, col)
	}
	sort.Strings(cols)
	parts := make([]string, 0, len(cols))
	for _, col := range cols {
		k, err := json.Marshal(col)
		if err != nil {
			return "?"
		}
		val, err := json.Marshal(v[col])
		if err != nil {
			return "?"
		}
		parts = append(parts, string(k)+":"+withMark(string(val), marks[col]))
	}
	return "{" + strings.Join(parts, ",") + "}"
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
