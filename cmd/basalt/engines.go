package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/guard"
)

// minEnginePrefix is the shortest engine id or fingerprint prefix basalt
// engine revoke accepts, so a typo cannot match an engine by chance.
const minEnginePrefix = 8

// sqlUndefinedTable is Postgres's undefined_table: a guard older than
// version 33 has no engines table or view.
const sqlUndefinedTable = "42P01"

// runEngineRecords: basalt engine list | revoke (CONTRACT.md, CLI, and
// basalt_meta "Version 33"). The engines recorded in the person's database
// and their revocation; basalt engine with no subcommand runs the engine.
func runEngineRecords(c *cliIO, args []string) int {
	switch args[0] {
	case "list":
		return engineList(c, args[1:])
	case "revoke":
		return engineRevoke(c, args[1:])
	}
	return c.fail(fmt.Errorf("%w: unknown engine command %q (list, revoke)", errUsage, args[0]))
}

// isEngineRecordsCommand reports whether basalt engine's arguments name a
// subcommand rather than the engine's own flags.
func isEngineRecordsCommand(args []string) bool {
	return len(args) > 0 && (args[0] == "list" || args[0] == "revoke")
}

// engineDTO is one engine in basalt engine list --json: public data only.
type engineDTO struct {
	EngineID    string     `json:"engineId"`
	Fingerprint string     `json:"fingerprint"`
	RecordedAt  time.Time  `json:"recordedAt"`
	RevokedAt   *time.Time `json:"revokedAt"`
	Self        bool       `json:"self"`
}

func engineFromDomain(e guard.RecordedEngine, self string) engineDTO {
	return engineDTO{
		EngineID: e.ID, Fingerprint: channel.FingerprintOf(e.ID),
		RecordedAt: e.RecordedAt, RevokedAt: e.RevokedAt, Self: self != "" && e.ID == self,
	}
}

func engineList(c *cliIO, args []string) int {
	fs, af := addAgentFlags(c, "engine list")
	admin := fs.Bool("admin", false, "read with the admin connection string (on your own computer, which has no agent credential)")
	asJSON := fs.Bool("json", false, "print the engines as JSON")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	conn, self, err := engineListConn(c, af, *admin)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	engines, err := guard.Engines(c.ctx, conn, *admin)
	if isUndefinedTable(err) {
		fmt.Fprintln(c.stderr, "basalt: this database records no engines (its guard is older than version 33; basalt upgrade adds them)")
		return exitOK
	}
	if err != nil {
		return c.fail(err)
	}
	out := make([]engineDTO, 0, len(engines))
	for _, e := range engines {
		out = append(out, engineFromDomain(e, self))
	}
	if *asJSON {
		return printJSONValue(c, out)
	}
	if len(out) == 0 {
		fmt.Fprintln(c.stderr, "basalt: no engine recorded; basalt init --setup-code records one")
		return exitOK
	}
	for _, e := range out {
		fmt.Fprintln(c.stdout, engineLine(e))
	}
	return exitOK
}

// engineListConn connects as the admin, or as the agent the flags name;
// as the agent it also returns this machine's engine id when its key file
// loads, so the list can mark it.
func engineListConn(c *cliIO, af agentFlags, admin bool) (*pgx.Conn, string, error) {
	if admin {
		conn, err := connectAdmin(c)
		return conn, "", err
	}
	dsn, err := agentURL(c, *af.agent, *af.credFile, *af.configPath)
	if err != nil {
		return nil, "", err
	}
	conn, err := connect(c.ctx, dsn)
	if err != nil {
		return nil, "", err
	}
	return conn, localEngineID(c, *af.configPath), nil
}

// localEngineID is the engine id of this machine's engine key file, read
// only when the config loads and this OS user owns the file; "" otherwise.
func localEngineID(c *cliIO, configPath string) string {
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return ""
	}
	path := filepath.Join(cfg.StateDirFor(c.goos), channel.KeyFileName)
	if _, err := os.Lstat(path); err != nil || !ownedByMe(path) {
		return ""
	}
	keys, err := channel.LoadKeys(path)
	if err != nil {
		return ""
	}
	return keys.EngineID()
}

func engineLine(e engineDTO) string {
	line := fmt.Sprintf("%s  recorded %s", e.Fingerprint, e.RecordedAt.UTC().Format(dateLayout))
	if e.RevokedAt != nil {
		line += "  revoked " + e.RevokedAt.UTC().Format(time.DateTime) + " UTC"
	}
	if e.Self {
		line += "  this engine"
	}
	return line
}

func isUndefinedTable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == sqlUndefinedTable
}

func engineRevoke(c *cliIO, args []string) int {
	fs := c.flags("engine revoke")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(idAfterFlags(fs, args)); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if fs.NArg() > 1 {
		return c.fail(fmt.Errorf("%w: give at most one engine (its id, or the start of its id or fingerprint)", errUsage))
	}
	conn, err := connectAdmin(c)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	if err := revokeEngine(c, conn, fs.Arg(0), *yes); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// revokeEngine finds the engine (asking which when none is named),
// confirms unless yes, and revokes it in Postgres.
func revokeEngine(c *cliIO, conn *pgx.Conn, ref string, yes bool) error {
	engines, err := guard.Engines(c.ctx, conn, true)
	if isUndefinedTable(err) {
		return errors.New("this database records no engines (its guard is older than version 33; basalt upgrade adds them)")
	}
	if err != nil {
		return err
	}
	active := activeEngines(engines)
	if ref == "" {
		if ref, err = askEngine(c, active); err != nil {
			return err
		}
	}
	e, err := findEngine(active, ref)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: engine %s, recorded %s\n", channel.FingerprintOf(e.ID), e.RecordedAt.UTC().Format(dateLayout))
	if !yes {
		ok, err := c.confirm(fmt.Sprintf("Revoke engine %s? A revoked engine is never recorded again.", channel.FingerprintOf(e.ID)))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("nothing was revoked")
		}
	}
	remaining, err := guard.RevokeEngine(c.ctx, conn, e.ID)
	if err != nil {
		return fmt.Errorf("the database refused: %s", pgDetail(err))
	}
	fmt.Fprintf(c.stderr, "basalt: engine %s revoked. %d engines remain recorded and not revoked.\n", channel.FingerprintOf(e.ID), remaining)
	fmt.Fprintln(c.stderr, "basalt: the engine reports ENGINE_REVOKED in status.")
	return nil
}

func activeEngines(engines []guard.RecordedEngine) []guard.RecordedEngine {
	out := make([]guard.RecordedEngine, 0, len(engines))
	for _, e := range engines {
		if e.RevokedAt == nil {
			out = append(out, e)
		}
	}
	return out
}

// askEngine lists the engines not revoked and reads the one the person
// types.
func askEngine(c *cliIO, active []guard.RecordedEngine) (string, error) {
	if len(active) == 0 {
		return "", errors.New("no engine is recorded and not revoked in this database")
	}
	for _, e := range active {
		fmt.Fprintf(c.stderr, "  %s  recorded %s\n", channel.FingerprintOf(e.ID), e.RecordedAt.UTC().Format(dateLayout))
	}
	fmt.Fprint(c.stderr, "Which engine? Type the start of its fingerprint: ")
	return c.line()
}

// findEngine is the engine whose id is ref, or whose id or fingerprint
// (spaces ignored) starts with ref, at least minEnginePrefix characters,
// matching exactly one.
func findEngine(active []guard.RecordedEngine, ref string) (guard.RecordedEngine, error) {
	ref = strings.ReplaceAll(ref, " ", "")
	var match []guard.RecordedEngine
	for _, e := range active {
		if e.ID == ref {
			return e, nil
		}
		if len(ref) >= minEnginePrefix && strings.HasPrefix(e.ID, ref) {
			match = append(match, e)
		}
	}
	switch len(match) {
	case 0:
		return guard.RecordedEngine{}, fmt.Errorf("no engine recorded and not revoked matches %q (give its id, or at least %d of its first characters, as basalt engine list --admin shows it)", ref, minEnginePrefix)
	case 1:
		return match[0], nil
	}
	return guard.RecordedEngine{}, fmt.Errorf("%q matches %d engines; give more of it", ref, len(match))
}
