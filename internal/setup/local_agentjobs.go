package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The fixes of the Update check (CONTRACT.md, The Update check): setup
// jobs for an agent of an engine with a config, each on check and run with
// the admin connection string.
const (
	JobLabels        = "LABELS"
	JobTrust         = "TRUST"
	JobRepair        = "REPAIR"
	JobPasskeyAdd    = "PASSKEY_ADD"
	JobPasskeyRemove = "PASSKEY_REMOVE"
)

// FixJobs are the Update check's fixes.
var FixJobs = []string{JobLabels, JobTrust, JobRepair, JobPasskeyAdd, JobPasskeyRemove}

func isFix(job string) bool { return slices.Contains(FixJobs, job) }

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

// agentJob is a validated UPDATE, REMOVE or fix: the agent as engine.json
// has it, and the database its credential connects to.
type agentJob struct {
	req    Request
	agent  config.Agent
	role   string
	names  guardmodel.Names
	target setupcode.Target
	// host is the admin string's host and port, lowercase: a PASSKEY_ADD
	// challenge is bound to it.
	host string
	// missing: the agent's credential file is gone (a REPAIR only).
	missing bool
	// others are the other agents of this engine whose credential connects
	// to the same database: a REMOVE drops their roles too, so it removes
	// them from engine.json with the agent.
	others []string
}

// isAgentJob: job is one an engine with a config runs for its agents.
func isAgentJob(job string) bool {
	return job == JobUpdate || job == JobRemove || slices.Contains(FixJobs, job)
}

// configuredAgent checks the agent and its OS user against engine.json, as
// every request of an engine with a config does (the jobs and doctor),
// before anything else: the agent must be this engine's, run as that OS
// user, on a person-operated engine that does not run as root.
func (s *LocalService) configuredAgent(agent, osUser string) (config.Agent, string, error) {
	if s.opts.Euid() == 0 {
		// A root engine reads its agents' files by other rules; it never
		// serves these jobs (engine.setupJobs), and this holds it here too.
		return config.Agent{}, "", refuse(CodeJobUnavailable, "An engine running as root never takes the admin connection string on this page.")
	}
	role, err := (guardmodel.Names{Prefix: s.opts.Prefix}).Agent(agent)
	if err != nil {
		return config.Agent{}, "", refuse(CodeInvalidArgument, "This setup link names an agent whose name cannot be used. Ask the agent for a new link.")
	}
	cfg, err := s.be.LoadConfig(s.opts.ConfigPath)
	if err != nil {
		return config.Agent{}, "", refuse(CodeSetupFailed, "This engine cannot read its config; nothing changed.")
	}
	if cfg.AgentOperated() {
		return config.Agent{}, "", refuse(CodeJobUnavailable, "This engine is operated by its agent, so the admin connection string never goes on this computer.")
	}
	i := slices.IndexFunc(cfg.Agents, func(a config.Agent) bool { return a.Name == agent })
	if i < 0 {
		return config.Agent{}, "", refuse(CodeInvalidArgument, fmt.Sprintf("This engine has no agent %s. Ask the agent to run basalt init --agent NAME with the name of the agent it uses.", agent))
	}
	a := cfg.Agents[i]
	if osUser == "" || osUser != a.OSUser {
		return config.Agent{}, "", refuse(CodeInvalidArgument, fmt.Sprintf("This link names another OS user than the one the agent %s runs as on this engine. Ask the agent for a new link.", agent))
	}
	return a, role, nil
}

// engineRemoved: a REMOVE deleted engine.json with the engine's last
// agent. The engine serves no agent any more and its removal job removes
// it from this computer (local_removed.go).
func (s *LocalService) engineRemoved() error {
	if err := s.be.Lstat(s.opts.ConfigPath); errors.Is(err, os.ErrNotExist) {
		return refuse(CodeEngineRemoved, "BasaltDB was removed from your database, and this engine is removing itself from this computer. To set BasaltDB up again, ask the agent to run basalt init.")
	}
	return nil
}

// validateAgentJob checks everything about an UPDATE, a REMOVE or a fix
// that needs no database, in order. The admin connection string must name
// the database the agent's own credential connects to, compared as the
// connect service compares a setup code's target (SameDatabase),
// before anything connects with it. run is a run's request, which may carry
// what its check does not.
func (s *LocalService) validateAgentJob(req Request, run bool) (agentJob, error) {
	if err := s.engineRemoved(); err != nil {
		return agentJob{}, err
	}
	if req.Job == JobChange {
		return agentJob{}, refuse(CodeInvalidArgument, "Pick Update or Remove on the page first.")
	}
	if req.Since != nil && (run || req.Job != "") {
		return agentJob{}, refuse(CodeInvalidArgument, "Only basalt init's probe, a check with no job, carries since.")
	}
	if req.Job == "" && s.resetAsked() {
		// basalt init's probe, after the person's "No, this isn't mine".
		return agentJob{}, refuse(CodeResetAsked, "You answered that this database is not yours. basalt init asks for your computer's administrator password next, to reset BasaltDB on this computer.")
	}
	if req.Job == "" && req.Since != nil && s.updatedSince(req.Agent, *req.Since) {
		// basalt init's probe, after the page's Update for its agent.
		return agentJob{}, refuse(CodeGuardUpdated, "The guard is updated. basalt init tells the agent to go on.")
	}
	if !isAgentJob(req.Job) {
		return agentJob{}, refuse(CodeJobUnavailable, alreadySetUp)
	}
	a, role, err := s.configuredAgent(req.Agent, req.OSUser)
	if err != nil {
		return agentJob{}, err
	}
	if req.Demo {
		return agentJob{}, refuse(CodeInvalidArgument, "An update, a removal or a fix never sets up the sample database. Ask the agent for a new link.")
	}
	if err := checkFields(req, run); err != nil {
		return agentJob{}, err
	}
	host, err := s.checkAdminURL(req.DatabaseURL, role)
	if err != nil {
		return agentJob{}, err
	}
	got, err := s.adminTarget(req.DatabaseURL)
	if err != nil {
		return agentJob{}, err
	}
	want, err := s.credentialTarget(a)
	missing := false
	switch {
	case err != nil && req.Job == JobRepair && errors.Is(err, os.ErrNotExist):
		// The credential file is gone: REPAIR writes a new one for the
		// database the admin string names, once that database holds this
		// engine's guard and the agent's role (CONTRACT.md, The Update check,
		// REPAIR).
		want, missing = got, true
	case err != nil:
		return agentJob{}, refuse(CodeSetupFailed, "This engine cannot read the agent's credential, so it cannot tell which database is the agent's. Nothing changed.")
	}
	if !SameDatabase(want, got) {
		return agentJob{}, refuse(CodeTargetMismatch, fmt.Sprintf("This admin connection string is for another database than the agent %s uses. Use the admin connection string of the agent's own database; nothing changed.", req.Agent))
	}
	j := agentJob{req: req, agent: a, role: role, names: guardmodel.Names{Prefix: s.opts.Prefix}, target: want, host: host, missing: missing}
	if req.Job != JobRemove {
		return j, nil
	}
	cfg, err := s.be.LoadConfig(s.opts.ConfigPath)
	if err != nil {
		return agentJob{}, refuse(CodeSetupFailed, "This engine cannot read its config; nothing changed.")
	}
	for _, o := range cfg.Agents {
		if o.Name == a.Name {
			continue
		}
		// An agent whose credential cannot be read cannot be served
		// either: it goes with the removal rather than stay behind.
		if t, err := s.credentialTarget(o); err != nil || SameDatabase(want, t) {
			j.others = append(j.others, o.Name)
		}
	}
	return j, nil
}

// The fields a request may carry besides the job, the agent, its OS user
// and the admin string.
const (
	fieldLabels = 1 << iota
	fieldTrustRoot
	fieldChallenge
	fieldPasskey
	fieldCredentialID
	fieldPinned
)

// fieldsOf are the optional fields req carries.
func fieldsOf(req Request) int {
	f := 0
	for _, set := range []struct {
		on  bool
		bit int
	}{
		{req.ColumnClasses != nil || req.RestPublic, fieldLabels},
		{req.TrustRoot != "", fieldTrustRoot},
		{req.Challenge != nil, fieldChallenge},
		{req.Passkey != nil, fieldPasskey},
		{req.CredentialID != "", fieldCredentialID},
		{req.Pinned != "", fieldPinned},
	} {
		if set.on {
			f |= set.bit
		}
	}
	return f
}

// allowedFields are the optional fields job's check (or run) carries
// (CONTRACT.md, The Update check).
func allowedFields(job string, run bool) int {
	switch job {
	case JobLabels:
		if run {
			return fieldLabels
		}
	case JobTrust:
		if run {
			return fieldTrustRoot | fieldPinned
		}
		return fieldTrustRoot
	case JobPasskeyAdd:
		if run {
			return fieldChallenge | fieldPasskey
		}
	case JobPasskeyRemove:
		return fieldCredentialID
	}
	return 0
}

// checkFields refuses a field the job does not take: an UPDATE and a
// REMOVE carry none, and a fix only the fields its screen gives it.
func checkFields(req Request, run bool) error {
	extra := fieldsOf(req) &^ allowedFields(req.Job, run)
	if req.Job == JobUpdate || req.Job == JobRemove {
		if extra != 0 || len(req.Answers) > 0 || req.Schemas != nil || req.Tables != nil {
			return refuse(CodeAnswersInvalid, "An update or a removal asks no question and registers no passkey.")
		}
		return nil
	}
	if extra != 0 || len(req.Answers) > 0 || req.Schemas != nil || req.Tables != nil || req.ConfirmName != "" {
		return refuse(CodeAnswersInvalid, "This fix does not take what the page sent. Reload the page and start again; nothing changed.")
	}
	return nil
}

// credentialTarget is the database the agent's credential connects to.
func (s *LocalService) credentialTarget(a config.Agent) (setupcode.Target, error) {
	dsn, err := s.be.ReadCredentialFile(a.Store.CredentialFile)
	if err != nil {
		return setupcode.Target{}, err
	}
	pc, err := s.be.ParseTarget(dsn)
	if err != nil {
		return setupcode.Target{}, err
	}
	return setupcode.ConnTarget(pc.Host, pc.Port, pc.Database, pc.User), nil
}

// adminTarget is the database the admin connection string connects to, as
// pgx would connect: one host, its port and the database.
func (s *LocalService) adminTarget(admin string) (setupcode.Target, error) {
	bad := refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
	pc, err := s.be.ParseTarget(admin)
	if err != nil {
		return setupcode.Target{}, bad
	}
	for _, fb := range pc.Fallbacks {
		if !strings.EqualFold(fb.Host, pc.Host) || fb.Port != pc.Port {
			return setupcode.Target{}, refuse(CodeConnectionStringRefused, "The admin connection string names more than one host; give the one database host the agent connects to.")
		}
	}
	return setupcode.ConnTarget(pc.Host, pc.Port, pc.Database, pc.User), nil
}

// agentPlan is what an UPDATE or REMOVE runs, read in the job's
// transaction.
type agentPlan struct {
	lines []string
	notes []string
	// UPDATE
	script            guardmodel.Script
	installed, latest int
	// REMOVE
	remove  RemovePlan
	removed []string
}

func (p agentPlan) sql(job string) string {
	if job == JobUpdate {
		return p.script.SQL()
	}
	return p.remove.SQL()
}

// planAgentJob reads the database for j in tx and changes nothing: the
// refusals, then what the job runs.
func (s *LocalService) planAgentJob(ctx context.Context, tx Tx, j agentJob, database string) (agentPlan, error) {
	if j.req.Job == JobUpdate {
		return s.planUpdate(ctx, tx, j, database)
	}
	if _, err := s.installedPrefix(ctx, tx); err != nil {
		return agentPlan{}, err
	}
	return s.planRemove(ctx, tx, j)
}

// installedPrefix is the prefix of the guard in the database, "" when it
// has none; another prefix than this engine's is PREFIX_MISMATCH.
func (s *LocalService) installedPrefix(ctx context.Context, tx Tx) (string, error) {
	prefix, err := s.be.InstalledPrefix(ctx, tx.Port())
	if err != nil {
		return "", s.setupFailed("read the guard prefix", err)
	}
	if prefix != "" && prefix != s.opts.Prefix {
		return "", refuse(CodePrefixMismatch, "This database's Basalt uses the prefix "+prefix+", not "+s.opts.Prefix+".")
	}
	return prefix, nil
}

// installedGuard is the version of this engine's guard in the database:
// another prefix is PREFIX_MISMATCH, no guard GUARD_MISSING (what names
// the job in the message, as "to update").
func (s *LocalService) installedGuard(ctx context.Context, tx Tx, database, what string) (int, error) {
	prefix, err := s.installedPrefix(ctx, tx)
	if err != nil {
		return 0, err
	}
	installed, err := s.be.InstalledVersion(ctx, tx.Port())
	if err != nil {
		return 0, s.setupFailed("read the guard version", err)
	}
	if prefix == "" || installed == 0 {
		return 0, refuse(CodeGuardMissing, fmt.Sprintf("The database %s has no Basalt guard %s. Nothing changed.", database, what))
	}
	return installed, nil
}

// agentRole refuses a database without the agent's role: it is not the
// agent's database.
func (s *LocalService) agentRole(ctx context.Context, tx Tx, j agentJob, database string) error {
	exists, err := s.be.AgentRoleExists(ctx, tx.Port(), j.names, j.req.Agent)
	if err != nil {
		return s.setupFailed("read the agent role", err)
	}
	if !exists {
		return refuse(CodeRoleMissing, fmt.Sprintf("The database %s has no role %s, so it is not the agent's database. Nothing changed.", database, j.role))
	}
	return nil
}

// planUpdate plans the basalt_meta migrations the build has and the
// database lacks, and nothing else: no password, grant, policy or passkey.
func (s *LocalService) planUpdate(ctx context.Context, tx Tx, j agentJob, database string) (agentPlan, error) {
	installed, err := s.installedGuard(ctx, tx, database, "to update")
	if err != nil {
		return agentPlan{}, err
	}
	if err := s.usable(ctx, tx); err != nil {
		return agentPlan{}, err
	}
	latest := s.be.LatestVersion()
	switch {
	case installed > latest:
		return agentPlan{}, refuse(CodeGuardNewer, fmt.Sprintf("The guard in the database %s (version %d) is newer than this engine (version %d): update BasaltDB on this computer instead. Nothing changed.", database, installed, latest))
	case installed == latest:
		return agentPlan{}, refuse(CodeGuardCurrent, fmt.Sprintf("The guard in the database %s is up to date (version %d); there is nothing to update.", database, installed))
	}
	if err := s.agentRole(ctx, tx, j, database); err != nil {
		return agentPlan{}, err
	}
	script, err := s.be.PlanInit(ctx, tx.Port(), guardmodel.InitOptions{Names: j.names})
	if err != nil {
		return agentPlan{}, s.setupFailed("plan the update", err)
	}
	return agentPlan{
		lines: []string{
			fmt.Sprintf("This updates Basalt's guard in the database %s from version %d to %d.", database, installed, latest),
			"It adds only the guard's missing migrations: it changes no password, grant or policy and registers no passkey. The agent " + j.req.Agent + " keeps working and needs no restart.",
		},
		notes: append([]string{}, script.Warnings...), script: script, installed: installed, latest: latest,
	}, nil
}

// planRemove plans the removal (PlanRemove: the guard's
// policies, basalt_meta, the roles and the marked sample schema), and
// says what this engine forgets. A database BasaltDB is already gone from
// (a removal whose engine.json write failed) plans only IF EXISTS drops,
// and the run finishes the removal on this engine.
func (s *LocalService) planRemove(ctx context.Context, tx Tx, j agentJob) (agentPlan, error) {
	rp, err := PlanRemove(ctx, s.be, tx.Port(), s.opts.Prefix)
	if err != nil {
		return agentPlan{}, err
	}
	removed := append([]string{j.req.Agent}, j.others...)
	lines := rp.Lines()
	if !rp.Installed {
		lines[0] = fmt.Sprintf("BasaltDB is no longer in the database %s. This finishes its removal on this computer.", rp.Database)
	}
	lines = append(lines,
		fmt.Sprintf("This engine stops serving %s and forgets %s: its credential is deleted. Nothing can undo this.", strings.Join(removed, ", "), plural(len(removed), "it", "them")),
	)
	return agentPlan{lines: lines, notes: []string{}, remove: rp, removed: removed}, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// checkAgentJob is the check of an UPDATE or REMOVE: it reads, in a
// transaction it rolls back, and changes nothing.
func (s *LocalService) checkAgentJob(ctx context.Context, req Request) (CheckAnswer, error) {
	j, err := s.validateAgentJob(req, false)
	if err != nil {
		return CheckAnswer{}, err
	}
	if isFix(req.Job) {
		return s.checkFix(ctx, j)
	}
	if req.ConfirmName != "" {
		return CheckAnswer{}, refuse(CodeAnswersInvalid, "The database name confirms a removal's run, not its check.")
	}
	conn, err := s.connect(ctx, req.DatabaseURL)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, s.setupFailed("begin", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	database, err := s.currentDatabase(ctx, tx)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	p, err := s.planAgentJob(ctx, tx, j, database)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	answer := CheckAnswer{
		Database: database, Lines: p.lines, SQL: p.sql(req.Job),
		Questions: []Question{}, Notes: p.notes, PasskeyNeeded: false,
	}
	if req.Job == JobRemove {
		// The page names the database and its host on the Remove button:
		// the admin string is the confirmation.
		answer.Host = j.host
	}
	return answer, nil
}

// runAgentJob runs an UPDATE or REMOVE: it repeats every check, plans
// again in the job's one transaction and applies the plan. A REMOVE then
// removes the agents it dropped from engine.json and deletes their
// credentials.
func (s *LocalService) runAgentJob(ctx context.Context, req Request) (RunAnswer, error) {
	j, err := s.validateAgentJob(req, true)
	if err != nil {
		return RunAnswer{}, err
	}
	if isFix(req.Job) {
		return s.runFix(ctx, j)
	}
	if req.ConfirmName != "" {
		return RunAnswer{}, refuse(CodeAnswersInvalid, "An update or a removal is confirmed by the admin connection string, not the database name.")
	}
	conn, err := s.connect(ctx, req.DatabaseURL)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var p agentPlan
	var database string
	demoKept := false
	err = beginFunc(ctx, conn, func(tx Tx) error {
		if database, err = s.currentDatabase(ctx, tx); err != nil {
			return err
		}
		if req.Job == JobRemove {
			// The admin string is the confirmation: no typed name.
			rp, kept, err := RunRemove(ctx, s.be, tx.Port(), s.opts.Prefix, "")
			if err != nil {
				return s.removeRefusal(err)
			}
			p, demoKept = agentPlan{remove: rp, removed: append([]string{j.req.Agent}, j.others...)}, kept
			return nil
		}
		if p, err = s.planAgentJob(ctx, tx, j, database); err != nil {
			return err
		}
		if err := ApplyInitTx(ctx, s.be, tx.Port(), p.script); err != nil {
			return s.setupFailed("update script", err)
		}
		return nil
	})
	if err != nil {
		return RunAnswer{}, timeLimit(ctx, s.asRefusal(err))
	}
	answer := RunAnswer{Agent: req.Agent, Warnings: []string{}, Passkeys: []RegisteredPasskey{}}
	if req.Job == JobUpdate {
		answer.Lines = []string{fmt.Sprintf("guard updated in the database %s from version %d to %d", database, p.installed, p.latest)}
		answer.Warnings = append(answer.Warnings, p.script.Warnings...)
		answer.MCPCommand = "basalt mcp --agent " + req.Agent
		return answer, nil
	}
	gone, err := s.forget(p.removed)
	if err != nil {
		r := refuse(CodeSetupFailed, "BasaltDB is removed from the database, but this engine could not remove the agent from its config. Open this link again to finish.")
		r.Internal = true
		return RunAnswer{}, r
	}
	answer.Lines = []string{fmt.Sprintf("BasaltDB removed from the database %s", database), "removed from this engine: " + strings.Join(p.removed, ", ")}
	answer.EngineRemoved = gone
	if gone {
		answer.EngineRemoving = s.askRemoval(&answer)
	}
	if demoKept {
		answer.Warnings = append(answer.Warnings, "the sample schema "+s.be.DemoSchema()+" stays: another object depends on it")
	}
	return answer, nil
}

// askRemoval creates the removal job's marker in the state folder, after
// the removal committed and engine.json is gone (CONTRACT.md, The local
// setup page, Removing the engine service): the root job then stops this
// engine and removes it from this computer. It reports whether the marker
// is there; when it is not, a warning says so and the engine stays,
// serving no agent.
func (s *LocalService) askRemoval(answer *RunAnswer) bool {
	if s.opts.StateDir == "" {
		return false
	}
	marker := filepath.Join(s.opts.StateDir, servicespec.RemovalMarkerName)
	if err := s.be.WriteFile(marker, nil); err != nil {
		answer.Warnings = append(answer.Warnings, "this engine could not ask to be removed from this computer, so it stays, serving no agent: "+err.Error())
		return false
	}
	return true
}

// removeRefusal is an internal/setup removal refusal as this page's.
func (s *LocalService) removeRefusal(err error) error {
	var r *SetuprunRefusalError
	if errors.As(err, &r) {
		out := refuse(r.Code, r.Message)
		if r.Code == CodeSetupFailed {
			out.Cause = causeOf("remove", r.Err, s.be.DatabaseError)
		}
		return out
	}
	return s.setupFailed("remove", err)
}

// forget removes agents from engine.json, then deletes their credential
// files. The config goes first: a run that stops between the two leaves
// only a credential no config names.
func (s *LocalService) forget(agents []string) (removedFile bool, err error) {
	cfg, err := s.be.LoadConfig(s.opts.ConfigPath)
	if err != nil {
		return false, err
	}
	var creds []string
	for _, a := range cfg.Agents {
		if slices.Contains(agents, a.Name) {
			creds = append(creds, a.Store.CredentialFile)
		}
	}
	removedFile, err = s.be.RemoveAgents(s.opts.ConfigPath, agents)
	if err != nil {
		return false, err
	}
	for _, c := range creds {
		_ = s.be.Remove(c)
		_ = s.be.Remove(c + ".pending")
	}
	return removedFile, nil
}
