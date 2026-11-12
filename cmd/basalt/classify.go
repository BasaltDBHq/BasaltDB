package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pii/classify"
	"github.com/basaltdbhq/basaltdb/internal/sqlguard"
)

// basalt classify (CONTRACT.md, PII classification, basalt classify): it
// suggests a class for every column the agents can read and records the
// classes the person confirms. The admin connection string is used for
// this run only and never written. No value from the person's tables is
// printed, logged or written: the review carries names and counts.

// piiGuardVersion is the first basalt_meta version with PII classification.
const piiGuardVersion = 15

// Review modes (--review).
const (
	reviewChanged = "changed"
	reviewAll     = "all"
	phoneAuto     = "auto"
)

// setList collects the repeatable --set flag.
type setList []string

func (s *setList) String() string     { return strings.Join(*s, ",") }
func (s *setList) Set(v string) error { *s = append(*s, v); return nil }

type classifyFlags struct {
	review, phoneRegion            string
	sets                           setList
	yes, dryRun, jsonOut, checkRun bool
}

// classSet is one --set: a column and the class it gets.
type classSet struct {
	column guard.ColumnKey
	class  string
	entity string
}

func parseClassify(c *cliIO, args []string) (classifyFlags, []classSet, error) {
	var f classifyFlags
	fs := c.flags("classify")
	fs.StringVar(&f.review, "review", reviewChanged, "which columns to show: changed or all")
	fs.Var(&f.sets, "set", "schema.table.column=class[:entity-type]; set a column's class without the review (repeatable)")
	fs.StringVar(&f.phoneRegion, "phone-region", phoneAuto, "region of phone numbers written without +cc: auto (inferred per column) or an ISO 3166 code")
	fs.BoolVar(&f.yes, "yes", false, "accept every suggestion shown without asking (needs-review columns keep the protected suggestion)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "print the review and write nothing")
	fs.BoolVar(&f.jsonOut, "json", false, "print the review as JSON on stdout and ask nothing")
	fs.BoolVar(&f.checkRun, "check", false, "check that sampled IDENTIFIER values round-trip to their token; writes nothing")
	if err := parse(fs, args); err != nil {
		return f, nil, err
	}
	if f.review != reviewChanged && f.review != reviewAll {
		return f, nil, fmt.Errorf("%w: --review must be changed or all", errUsage)
	}
	if f.checkRun {
		f.review = reviewAll // the check covers every IDENTIFIER column, so all are shown
	}
	if f.phoneRegion != phoneAuto {
		f.phoneRegion = strings.ToUpper(f.phoneRegion)
		if !classify.ValidRegion(f.phoneRegion) {
			return f, nil, fmt.Errorf("%w: --phone-region must be auto or an ISO 3166-1 alpha-2 region code (ID, US, EE, …)", errUsage)
		}
	}
	sets := make([]classSet, 0, len(f.sets))
	for _, s := range f.sets {
		cs, err := parseSet(s)
		if err != nil {
			return f, nil, fmt.Errorf("%w: --set %w", errUsage, err)
		}
		sets = append(sets, cs)
	}
	return f, sets, nil
}

// The CLI spelling of classes and entity types (CONTRACT.md, Classes).
var (
	classSpelling = map[string]string{
		"public": guard.ClassPublic, "identifier": guard.ClassIdentifier, "free-text": guard.ClassFreeText,
		"secret": guard.ClassSecret, "unclassified": guard.ClassUnclassified,
	}
	entitySpelling = map[string]string{
		"email": guard.EntityEmail, "phone": guard.EntityPhone, "person-name": guard.EntityPersonName,
		"address": guard.EntityAddress, "other": guard.EntityOther,
	}
)

// spellEntity is the CLI spelling of an entity type.
func spellEntity(entity string) string { return strings.ToLower(strings.ReplaceAll(entity, "_", "-")) }

// parseClass reads class[:entity-type]: the entity type is required with
// identifier and refused with any other class.
func parseClass(s string) (class, entity string, err error) {
	c, e, hasEntity := strings.Cut(strings.ToLower(strings.TrimSpace(s)), ":")
	class, ok := classSpelling[c]
	if !ok {
		return "", "", fmt.Errorf("%q is no class: use public, identifier:<entity-type>, free-text, secret or unclassified", c)
	}
	switch {
	case class == guard.ClassIdentifier && !hasEntity:
		return "", "", errors.New("identifier needs an entity type: identifier:email, phone, person-name, address or other")
	case class != guard.ClassIdentifier && hasEntity:
		return "", "", fmt.Errorf("only identifier takes an entity type, not %s", c)
	case !hasEntity:
		return class, "", nil
	}
	entity, ok = entitySpelling[e]
	if !ok {
		return "", "", fmt.Errorf("%q is no entity type: use email, phone, person-name, address or other", e)
	}
	return class, entity, nil
}

func parseSet(s string) (classSet, error) {
	i := strings.LastIndexByte(s, '=')
	if i < 0 {
		return classSet{}, fmt.Errorf("%q: write schema.table.column=class[:entity-type]", s)
	}
	parts := strings.SplitN(s[:i], ".", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return classSet{}, fmt.Errorf("%q: name the column as schema.table.column", s[:i])
	}
	class, entity, err := parseClass(s[i+1:])
	if err != nil {
		return classSet{}, err
	}
	return classSet{column: guard.ColumnKey{Schema: parts[0], Table: parts[1], Column: parts[2]}, class: class, entity: entity}, nil
}

func runClassify(c *cliIO, args []string) int {
	f, sets, err := parseClassify(c, args)
	if err != nil {
		return c.fail(err)
	}
	admin, err := c.adminURL()
	if err != nil {
		return c.fail(err)
	}
	if _, err := guard.AgentConnString(admin, "", ""); err != nil {
		return c.fail(err)
	}
	conn, err := c.dial(c.ctx, admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	if err := classifyColumns(c, conn, f, sets); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// classifyGuard checks the guard has PII classification and returns its
// names.
func classifyGuard(c *cliIO, conn *pgx.Conn) (guard.Names, error) {
	prefix, err := guard.InstalledPrefix(c.ctx, conn)
	if err != nil {
		return guard.Names{}, err
	}
	installed, err := guard.InstalledVersion(c.ctx, conn)
	if err != nil {
		return guard.Names{}, err
	}
	switch latest := guard.LatestVersion(); {
	case installed < piiGuardVersion || prefix == "":
		return guard.Names{}, fmt.Errorf("guard schema v%d has no PII classification; run basalt init again to upgrade it (same flags as before)", installed)
	case installed > latest:
		return guard.Names{}, newerGuardError(installed, latest)
	}
	names := guard.Names{Prefix: prefix}
	if names.Validate() != nil {
		return guard.Names{}, fmt.Errorf("basalt_meta in this database is owned by %s, not by a Basalt guard role", prefix)
	}
	return names, nil
}

// classifyRun is everything one run computed.
type classifyRun struct {
	f       classifyFlags
	names   guard.Names
	state   guard.ClassificationState
	results []classify.Result
	tables  []classify.ReviewTable
	checks  map[string]classify.CheckResult
}

func classifyColumns(c *cliIO, conn *pgx.Conn, f classifyFlags, sets []classSet) error {
	run := classifyRun{f: f}
	var err error
	if run.names, err = classifyGuard(c, conn); err != nil {
		return err
	}
	err = pgx.BeginTxFunc(c.ctx, conn, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		run.state, err = guard.ReadClassification(c.ctx, tx, run.names)
		return err
	})
	if err != nil {
		return err
	}
	cols, err := readableColumns(c, conn, run.state, sets)
	if err != nil {
		return err
	}
	opts := classify.Options{}
	if f.phoneRegion != phoneAuto {
		opts.PhoneRegion = f.phoneRegion
	}
	sampler := classify.Sampler{Conn: conn, Timeout: sqlguard.DefaultStatementTimeout}
	run.results, err = classify.SuggestAll(c.ctx, cols, sampler.Sample, opts, func(col classify.Column, s classify.Suggestion) bool {
		_, ok := run.checkTarget(col, s)
		return f.checkRun && ok
	})
	if err != nil {
		return err
	}
	run.tables = classify.BuildReview(run.results, run.state.Stored, f.review == reviewAll || len(sets) > 0)
	if f.checkRun {
		run.checks, err = classify.Check(run.results, func(r classify.Result) (classify.CheckTarget, bool) {
			return run.checkTarget(r.Column, r.Suggestion)
		})
		if err != nil {
			return err
		}
	}
	decided, write, err := run.decide(c, sets)
	if err != nil {
		return err
	}
	var rows []guard.PIIColumn
	if write {
		rows = classify.Rows(run.tables, decided)
		err := pgx.BeginFunc(c.ctx, conn, func(tx pgx.Tx) error {
			return guard.WriteClassification(c.ctx, tx, run.names, guard.Classification{Columns: rows, At: c.now()})
		})
		if err != nil {
			return fmt.Errorf("write the classes: %w; nothing written", err)
		}
	}
	return run.finish(c, rows, write)
}

// readableColumns are the columns to suggest for: every readable column, or
// only the --set ones, which must be readable.
func readableColumns(c *cliIO, conn *pgx.Conn, st guard.ClassificationState, sets []classSet) ([]classify.Column, error) {
	keys, err := classify.KeyColumns(c.ctx, conn)
	if err != nil {
		return nil, err
	}
	wanted := map[guard.ColumnKey]bool{}
	for _, s := range sets {
		wanted[s.column] = true
	}
	cols := make([]classify.Column, 0, len(st.Readable))
	for _, r := range st.Readable {
		k := guard.ColumnKey{Schema: r.Schema, Table: r.Table, Column: r.Column}
		if len(sets) > 0 && !wanted[k] {
			continue
		}
		delete(wanted, k)
		cols = append(cols, classify.Column{
			Schema: r.Schema, Table: r.Table, Name: r.Column, DataType: r.DataType,
			Key: keys[classify.KeyRef{TableOID: r.TableOID, Attnum: r.Attnum}],
		})
	}
	for _, s := range sets {
		if wanted[s.column] {
			return nil, fmt.Errorf("%w: --set %s.%s.%s: no agent can read that column", errUsage, s.column.Schema, s.column.Table, s.column.Column)
		}
	}
	return cols, nil
}

// checkTarget is how --check tokenizes a column: as the IDENTIFIER class a
// person confirmed, else as the IDENTIFIER suggestion; other columns are
// not checked.
func (r classifyRun) checkTarget(col classify.Column, s classify.Suggestion) (classify.CheckTarget, bool) {
	region := func(stored string) string {
		if r.f.phoneRegion != phoneAuto {
			return r.f.phoneRegion
		}
		return stored
	}
	st, ok := r.state.Stored[guard.ColumnKey{Schema: col.Schema, Table: col.Table, Column: col.Name}]
	if ok && st.Class == guard.ClassIdentifier {
		return classify.CheckTarget{EntityType: st.EntityType, PhoneRegion: region(st.PhoneRegion)}, true
	}
	if s.Class == guard.ClassIdentifier {
		return classify.CheckTarget{EntityType: s.EntityType, PhoneRegion: region(s.PhoneRegion)}, true
	}
	return classify.CheckTarget{}, false
}

// decide works out the classes of this run and whether it writes: --set
// columns, every suggestion with --yes, the person's answers at a terminal.
// --dry-run and --check never write; --json asks nothing.
func (r classifyRun) decide(c *cliIO, sets []classSet) (map[string]classify.Decision, bool, error) {
	f := r.f
	decided := map[string]classify.Decision{}
	readOnly := f.dryRun || f.checkRun
	switch {
	case len(sets) > 0:
		for _, s := range sets {
			name := s.column.Schema + "." + s.column.Table + "." + s.column.Column
			decided[name] = classify.Decision{Class: s.class, EntityType: s.entity, PhoneRegion: r.phoneRegionOf(name)}
		}
		return decided, !readOnly, nil
	case f.yes:
		for _, t := range r.tables {
			for _, col := range t.Columns {
				decided[col.Column.FullName()] = col.Protected()
			}
		}
		return r.fixRegions(decided), !readOnly, nil
	case f.jsonOut || readOnly || len(r.tables) == 0:
		return nil, false, nil
	case !r.asks(c):
		r.printReview(c.stdout, c.width())
		return nil, false, errors.New("no terminal to confirm the classes; pass --yes to accept the suggestions or --set to set columns")
	}
	if err := r.ask(c, decided); err != nil {
		return nil, false, err
	}
	return r.fixRegions(decided), true, nil
}

// fixRegions gives every PHONE decision the --phone-region, when one is set.
func (r classifyRun) fixRegions(decided map[string]classify.Decision) map[string]classify.Decision {
	if r.f.phoneRegion == phoneAuto {
		return decided
	}
	for name, d := range decided {
		if d.EntityType == guard.EntityPhone {
			d.PhoneRegion = r.f.phoneRegion
			decided[name] = d
		}
	}
	return decided
}

// asks reports whether this run asks the person at the terminal.
func (r classifyRun) asks(c *cliIO) bool {
	f := r.f
	return c.interactive && len(f.sets) == 0 && !f.yes && !f.jsonOut && !f.dryRun && !f.checkRun && len(r.tables) > 0
}

// phoneRegionOf is the region a --set PHONE column gets: --phone-region, or
// the one inferred from its sample, or the one stored.
func (r classifyRun) phoneRegionOf(name string) string {
	if r.f.phoneRegion != phoneAuto {
		return r.f.phoneRegion
	}
	for _, t := range r.tables {
		for _, col := range t.Columns {
			if col.Column.FullName() != name {
				continue
			}
			if col.Suggestion.PhoneRegion != "" {
				return col.Suggestion.PhoneRegion
			}
			if col.Stored != nil {
				return col.Stored.PhoneRegion
			}
		}
	}
	return ""
}

// finish prints what the run did: the JSON review, or the text review
// (unless the terminal review printed it already), the check and counts.
func (r classifyRun) finish(c *cliIO, rows []guard.PIIColumn, written bool) error {
	f := r.f
	if f.jsonOut {
		out := classify.JSONFromReview(r.tables, classify.ReviewMeta{
			Fingerprint: r.state.Fingerprint, Previous: r.state.Previous, Review: strings.ToUpper(f.review),
			DryRun: f.dryRun, Written: written,
		}, rows, r.checks)
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	if !r.asks(c) {
		r.printReview(c.stdout, c.width()) // the terminal review printed it as it asked
	}
	if f.checkRun {
		printChecks(c.stdout, r.tables, r.checks)
	}
	switch {
	case f.dryRun || f.checkRun:
		fmt.Fprintln(c.stderr, "basalt: nothing written (--dry-run or --check)")
	case written:
		printWritten(c.stderr, rows)
	}
	return nil
}

func printWritten(w io.Writer, rows []guard.PIIColumn) {
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.Class]++
	}
	classified := len(rows) - counts[guard.ClassUnclassified]
	fmt.Fprintf(w, "basalt: classified %d columns (%d PUBLIC, %d IDENTIFIER, %d FREE_TEXT, %d SECRET); %d columns stay UNCLASSIFIED\n",
		classified, counts[guard.ClassPublic], counts[guard.ClassIdentifier], counts[guard.ClassFreeText],
		counts[guard.ClassSecret], counts[guard.ClassUnclassified])
}

func printChecks(w io.Writer, tables []classify.ReviewTable, checks map[string]classify.CheckResult) {
	if len(checks) == 0 {
		fmt.Fprintln(w, "Round trip: no IDENTIFIER column to check.")
		return
	}
	fmt.Fprintln(w, "Round trip (value → token → value → token), counts only:")
	for _, t := range tables {
		for _, col := range t.Columns {
			ck, ok := checks[col.Column.FullName()]
			if !ok {
				continue
			}
			line := fmt.Sprintf("  %s: %d sampled, %d do not round-trip", col.Column.FullName(), ck.Sampled, ck.RoundTripFailures)
			if ck.CommonWordRule > 0 {
				line += fmt.Sprintf(" (%d single common words: the common-word rule)", ck.CommonWordRule)
			}
			fmt.Fprintln(w, line)
		}
	}
}
