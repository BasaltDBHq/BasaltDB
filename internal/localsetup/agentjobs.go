package localsetup

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/demo"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// The refusals of UPDATE and REMOVE (CONTRACT.md, The local setup page,
// Errors). TARGET_MISMATCH and ROLE_MISSING mean what the connect service's
// do; the GUARD_ codes are this page's own.
const (
	CodeTargetMismatch = "TARGET_MISMATCH"
	CodeRoleMissing    = "ROLE_MISSING"
	CodeGuardMissing   = "GUARD_MISSING"
	CodeGuardCurrent   = "GUARD_CURRENT"
	CodeGuardNewer     = "GUARD_NEWER"
)

// alreadySetUp is the refusal of an INSTALL, or of a job the page does not
// know, on an engine that has a config.
const alreadySetUp = "This engine is already set up. An install never changes an engine that has a config; ask the agent for the setup link of the change you want."

// agentJob is a validated UPDATE or REMOVE: the agent as engine.json has
// it, and the database its credential connects to.
type agentJob struct {
	req    Request
	agent  config.Agent
	role   string
	names  guard.Names
	target setupcode.Target
	// others are the other agents of this engine whose credential connects
	// to the same database: a REMOVE drops their roles too, so it removes
	// them from engine.json with the agent.
	others []string
}

// validateAgentJob checks everything about an UPDATE or REMOVE that needs
// no database, in order. The admin connection string must name the
// database the agent's own credential connects to, compared as the
// connect service compares a setup code's target (setuprun.SameDatabase),
// before anything connects with it.
func (s *Service) validateAgentJob(req Request) (agentJob, error) {
	if req.Job != JobUpdate && req.Job != JobRemove {
		return agentJob{}, refuse(CodeJobUnavailable, alreadySetUp)
	}
	names := guard.Names{Prefix: s.opts.Prefix}
	role, err := names.Agent(req.Agent)
	if err != nil {
		return agentJob{}, refuse(CodeInvalidArgument, "This setup link names an agent whose name cannot be used. Ask the agent for a new link.")
	}
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		return agentJob{}, refuse(CodeSetupFailed, "This engine cannot read its config; nothing changed.")
	}
	if cfg.AgentOperated() {
		return agentJob{}, refuse(CodeJobUnavailable, "This engine is operated by its agent, so the admin connection string never goes on this computer.")
	}
	i := slices.IndexFunc(cfg.Agents, func(a config.Agent) bool { return a.Name == req.Agent })
	if i < 0 {
		return agentJob{}, refuse(CodeInvalidArgument, fmt.Sprintf("This engine has no agent %s. Ask the agent for a new link.", req.Agent))
	}
	a := cfg.Agents[i]
	if req.OSUser == "" || req.OSUser != a.OSUser {
		return agentJob{}, refuse(CodeInvalidArgument, fmt.Sprintf("This link names another OS user than the one the agent %s runs as on this engine. Ask the agent for a new link.", req.Agent))
	}
	if req.Demo {
		return agentJob{}, refuse(CodeInvalidArgument, "An update or a removal never sets up the sample database. Ask the agent for a new link.")
	}
	if len(req.Answers) > 0 || req.Challenge != nil || req.Passkey != nil {
		return agentJob{}, refuse(CodeAnswersInvalid, "An update or a removal asks no question and registers no passkey.")
	}
	if _, err := checkAdminURL(req.DatabaseURL, role); err != nil {
		return agentJob{}, err
	}
	want, err := credentialTarget(a)
	if err != nil {
		return agentJob{}, refuse(CodeSetupFailed, "This engine cannot read the agent's credential, so it cannot tell which database is the agent's. Nothing changed.")
	}
	got, err := adminTarget(req.DatabaseURL)
	if err != nil {
		return agentJob{}, err
	}
	if !setuprun.SameDatabase(want, got) {
		return agentJob{}, refuse(CodeTargetMismatch, fmt.Sprintf("This admin connection string is for another database than the agent %s uses. Use the admin connection string of the agent's own database; nothing changed.", req.Agent))
	}
	j := agentJob{req: req, agent: a, role: role, names: names, target: want}
	if req.Job == JobRemove {
		for _, o := range cfg.Agents {
			if o.Name == a.Name {
				continue
			}
			if t, err := credentialTarget(o); err == nil && setuprun.SameDatabase(want, t) {
				j.others = append(j.others, o.Name)
			}
		}
	}
	return j, nil
}

// credentialTarget is the database the agent's credential connects to.
func credentialTarget(a config.Agent) (setupcode.Target, error) {
	dsn, err := config.ReadCredential(a.Store.CredentialFile)
	if err != nil {
		return setupcode.Target{}, err
	}
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return setupcode.Target{}, err
	}
	return setupcode.ConnTarget(pc.Host, int(pc.Port), pc.Database, pc.User), nil
}

// adminTarget is the database the admin connection string connects to, as
// pgx would connect: one host, its port and the database.
func adminTarget(admin string) (setupcode.Target, error) {
	bad := refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
	pc, err := pgconn.ParseConfig(admin)
	if err != nil {
		return setupcode.Target{}, bad
	}
	for _, fb := range pc.Fallbacks {
		if !strings.EqualFold(fb.Host, pc.Host) || fb.Port != pc.Port {
			return setupcode.Target{}, refuse(CodeConnectionStringRefused, "The admin connection string names more than one host; give the one database host the agent connects to.")
		}
	}
	return setupcode.ConnTarget(pc.Host, int(pc.Port), pc.Database, pc.User), nil
}

// agentPlan is what an UPDATE or REMOVE runs, read in the job's
// transaction.
type agentPlan struct {
	lines []string
	notes []string
	// UPDATE
	script            guard.Script
	installed, latest int
	// REMOVE
	demoDrops, drops []string
	removed          []string
}

func (p agentPlan) sql(job string) string {
	if job == JobUpdate {
		return p.script.SQL()
	}
	var b strings.Builder
	for _, sql := range append(slices.Clone(p.drops), p.demoDrops...) {
		b.WriteString(sql + ";\n")
	}
	return b.String()
}

// planAgentJob reads the database for j in tx and changes nothing: the
// refusals, then what the job runs.
func (s *Service) planAgentJob(ctx context.Context, tx pgx.Tx, j agentJob, database string) (agentPlan, error) {
	prefix, err := guard.InstalledPrefix(ctx, tx)
	if err != nil {
		return agentPlan{}, setupFailed()
	}
	if prefix != "" && prefix != s.opts.Prefix {
		return agentPlan{}, refuse(CodePrefixMismatch, "This database's Basalt uses the prefix "+prefix+", not "+s.opts.Prefix+".")
	}
	if j.req.Job == JobUpdate {
		return s.planUpdate(ctx, tx, j, prefix, database)
	}
	return s.planRemove(ctx, tx, j, prefix, database)
}

// planUpdate plans the basalt_meta migrations the build has and the
// database lacks, and nothing else: no password, grant, policy or passkey.
func (s *Service) planUpdate(ctx context.Context, tx pgx.Tx, j agentJob, prefix, database string) (agentPlan, error) {
	installed, err := guard.InstalledVersion(ctx, tx)
	if err != nil {
		return agentPlan{}, setupFailed()
	}
	latest := guard.LatestVersion()
	switch {
	case prefix == "" || installed == 0:
		return agentPlan{}, refuse(CodeGuardMissing, fmt.Sprintf("The database %s has no Basalt guard to update. Nothing changed.", database))
	case installed > latest:
		return agentPlan{}, refuse(CodeGuardNewer, fmt.Sprintf("The guard in the database %s (version %d) is newer than this engine (version %d): update BasaltDB on this computer instead. Nothing changed.", database, installed, latest))
	case installed == latest:
		return agentPlan{}, refuse(CodeGuardCurrent, fmt.Sprintf("The guard in the database %s is up to date (version %d); there is nothing to update.", database, installed))
	}
	exists, err := guard.AgentRoleExists(ctx, tx, j.names, j.req.Agent)
	if err != nil {
		return agentPlan{}, setupFailed()
	}
	if !exists {
		return agentPlan{}, refuse(CodeRoleMissing, fmt.Sprintf("The database %s has no role %s, so it is not the agent's database. Nothing changed.", database, j.role))
	}
	script, err := guard.PlanInit(ctx, tx, guard.InitOptions{Names: j.names})
	if err != nil {
		return agentPlan{}, setupFailed()
	}
	return agentPlan{
		lines: []string{
			fmt.Sprintf("This updates Basalt's guard in the database %s from version %d to %d.", database, installed, latest),
			"It adds only the guard's missing migrations: it changes no password, grant or policy and registers no passkey. The agent " + j.req.Agent + " keeps working and needs no restart.",
		},
		notes: append([]string{}, script.Warnings...), script: script, installed: installed, latest: latest,
	}, nil
}

// planRemove plans the removal: the guard's policies, basalt_meta and the
// roles (guard.PlanUninstall), then the sample schema when the demo made
// it. The guard's drops run first, so a policy they drop on a sample table
// is still there to drop.
// A database Basalt is already gone from (a removal whose engine.json write
// failed) plans only the IF EXISTS drop, and the run finishes the removal
// on this engine.
func (s *Service) planRemove(ctx context.Context, tx pgx.Tx, j agentJob, prefix, database string) (agentPlan, error) {
	demoDrops, err := demo.PlanDrop(ctx, tx)
	if err != nil {
		return agentPlan{}, setupFailed()
	}
	drops, err := guard.PlanUninstall(ctx, tx, j.names)
	if err != nil {
		return agentPlan{}, setupFailed()
	}
	removed := append([]string{j.req.Agent}, j.others...)
	var lines []string
	if prefix == "" {
		lines = append(lines, fmt.Sprintf("Basalt is no longer in the database %s. This finishes its removal on this computer.", database))
	} else {
		lines = append(lines, fmt.Sprintf("This removes Basalt from the database %s: the guard's row-level security policies, the schema basalt_meta with the ledger of every action, and every %s_ role.", database, s.opts.Prefix))
	}
	if len(demoDrops) > 0 {
		lines = append(lines, "It drops the sample schema "+demo.Schema+" with its rows, which the sample-database setup made. If another object depends on it, the schema stays.")
	}
	lines = append(lines,
		fmt.Sprintf("This engine stops serving %s and forgets %s: its credential is deleted. Nothing can undo this.", strings.Join(removed, ", "), plural(len(removed), "it", "them")),
	)
	return agentPlan{lines: lines, notes: []string{}, demoDrops: demoDrops, drops: drops, removed: removed}, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// checkAgentJob is the check of an UPDATE or REMOVE: it reads, in a
// transaction it rolls back, and changes nothing.
func (s *Service) checkAgentJob(ctx context.Context, req Request) (CheckAnswer, error) {
	j, err := s.validateAgentJob(req)
	if err != nil {
		return CheckAnswer{}, err
	}
	conn, err := s.connect(ctx, req.DatabaseURL)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	database, err := currentDatabase(ctx, tx)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	p, err := s.planAgentJob(ctx, tx, j, database)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	return CheckAnswer{
		Database: database, Lines: p.lines, SQL: p.sql(req.Job),
		Questions: []Question{}, Notes: p.notes, PasskeyNeeded: false,
	}, nil
}

// runAgentJob runs an UPDATE or REMOVE: it repeats every check, plans
// again in the job's one transaction and applies the plan. A REMOVE then
// removes the agents it dropped from engine.json and deletes their
// credentials.
func (s *Service) runAgentJob(ctx context.Context, req Request) (RunAnswer, error) {
	j, err := s.validateAgentJob(req)
	if err != nil {
		return RunAnswer{}, err
	}
	conn, err := s.connect(ctx, req.DatabaseURL)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var p agentPlan
	var database string
	demoKept := false
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if database, err = currentDatabase(ctx, tx); err != nil {
			return err
		}
		if p, err = s.planAgentJob(ctx, tx, j, database); err != nil {
			return err
		}
		if req.Job == JobUpdate {
			if err := setuprun.ApplyInitTx(ctx, tx, p.script); err != nil {
				return setupFailed()
			}
			return nil
		}
		for _, sql := range p.drops {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return refuse(CodeSetupFailed, "Removing Basalt failed, for example because one of its roles still has privileges in another database; nothing changed.")
			}
		}
		if demoKept, err = demo.ApplyDrop(ctx, tx, p.demoDrops); err != nil {
			return setupFailed()
		}
		return nil
	})
	if err != nil {
		return RunAnswer{}, timeLimit(ctx, AsRefusal(err))
	}
	answer := RunAnswer{Agent: req.Agent, Warnings: []string{}, Passkeys: []RegisteredPasskey{}}
	if req.Job == JobUpdate {
		answer.Lines = []string{fmt.Sprintf("guard updated in the database %s from version %d to %d", database, p.installed, p.latest)}
		answer.Warnings = append(answer.Warnings, p.script.Warnings...)
		answer.MCPCommand = "basalt mcp --agent " + req.Agent
		return answer, nil
	}
	if err := s.forget(p.removed); err != nil {
		r := refuse(CodeSetupFailed, "Basalt is removed from the database, but this engine could not remove the agent from its config. Open this link again to finish.")
		r.Status = http.StatusInternalServerError
		return RunAnswer{}, r
	}
	answer.Lines = []string{fmt.Sprintf("Basalt removed from the database %s", database), "removed from this engine: " + strings.Join(p.removed, ", ")}
	if demoKept {
		answer.Warnings = append(answer.Warnings, "the sample schema "+demo.Schema+" stays: another object depends on it")
	}
	return answer, nil
}

// forget removes agents from engine.json, then deletes their credential
// files. The config goes first: a run that stops between the two leaves
// only a credential no config names.
func (s *Service) forget(agents []string) error {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		return err
	}
	var creds []string
	for _, a := range cfg.Agents {
		if slices.Contains(agents, a.Name) {
			creds = append(creds, a.Store.CredentialFile)
		}
	}
	if _, err := config.RemoveAgents(s.opts.ConfigPath, agents); err != nil {
		return err
	}
	for _, c := range creds {
		_ = os.Remove(c)
		_ = os.Remove(c + ".pending")
	}
	return nil
}
