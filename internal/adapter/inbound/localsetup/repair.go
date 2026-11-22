package localsetup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/service/setuprun"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// REPAIR: an agent that can't log in (CONTRACT.md, The Update check). The
// database refuses the agent's credential, so the fix sets a new password
// on the agent's role and writes it to the credential. It changes no
// grant, policy, label or passkey.

// repairable refuses a fix the agent's credential does not need: a
// credential that logs in as the agent's role is NOTHING_TO_FIX, and one
// the engine cannot try (the database unreachable, its certificate not
// verified) is that refusal. A login the database refuses is repairable.
func (s *Service) repairable(ctx context.Context, j agentJob) (string, error) {
	if j.missing {
		return "", nil // no credential to try: the fix writes a new one
	}
	dsn, err := config.ReadCredential(j.agent.Store.CredentialFile)
	if err != nil {
		return "", refuse(CodeSetupFailed, "This engine cannot read the agent's credential, so it cannot tell which database is the agent's. Nothing changed.")
	}
	if s.be.CheckForeignDSN(dsn) != nil {
		return "", refuse(CodeSetupFailed, "The agent's credential on this computer is not one this engine wrote. Nothing changed.")
	}
	conn, err := s.opts.Dial(ctx, dsn)
	var pg *pgconn.PgError
	switch {
	case err == nil:
		defer conn.Close(context.WithoutCancel(ctx))
		var user string
		if err := conn.QueryRow(ctx, `SELECT current_user::text`).Scan(&user); err == nil && user == j.role {
			return "", nothingToFix()
		}
	case errors.As(err, &pg) && len(pg.Code) >= 2 && pg.Code[:2] == "28":
		// The database refuses the credential: the fix applies.
	case s.be.CertificateNotVerified(err):
		return "", refuse(CodeCertificateNotVerified, "The database's TLS certificate could not be verified, so the agent's login was not tried. Check the certificate first; nothing changed.")
	default:
		return "", timeLimit(ctx, refuse(CodeDatabaseUnreachable, "The database could not be reached with the agent's credential, so its login was not tried. Nothing changed."))
	}
	return dsn, nil
}

// repairPlan is the REPAIR script for a new password, with its words.
func (s *Service) repairPlan(j agentJob, password string) (setuprun.Script, []string, error) {
	script, err := s.be.RepairScript(j.names, j.req.Agent, password, statementTimeout.Milliseconds())
	if err != nil {
		return setuprun.Script{}, nil, setupFailed("plan the repair", err)
	}
	lines := []string{fmt.Sprintf("This sets a new password for %s. Only this computer's BasaltDB knows it.", j.role)}
	if j.missing {
		lines = append(lines, fmt.Sprintf("This computer's BasaltDB has no credential for %s any more: it writes a new one for this database.", j.req.Agent))
	}
	return script, lines, nil
}

func (s *Service) checkRepair(ctx context.Context, j agentJob) (CheckAnswer, error) {
	if _, err := s.repairable(ctx, j); err != nil {
		return CheckAnswer{}, err
	}
	conn, err := s.connect(ctx, j.req.DatabaseURL)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, setupFailed("begin", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	database, err := s.fixDatabase(ctx, tx, j)
	if err != nil {
		return CheckAnswer{}, timeLimit(ctx, err)
	}
	// A throwaway password: the shown SQL redacts it, and nothing commits.
	script, lines, err := s.repairPlan(j, s.be.NewPassword())
	if err != nil {
		return CheckAnswer{}, err
	}
	return fixAnswer(database, lines, script.SQL()), nil
}

// runRepair sets the new password in one transaction and writes the
// credential before the commit, as the install does: a known failure puts
// the old credential back, and a commit whose answer was lost keeps the new
// one, which may be the role's only password now.
func (s *Service) runRepair(ctx context.Context, j agentJob) (RunAnswer, error) {
	dsn, err := s.repairable(ctx, j)
	if err != nil {
		return RunAnswer{}, err
	}
	password := s.be.NewPassword()
	next, err := s.newCredential(j, dsn, password)
	if err != nil {
		return RunAnswer{}, err
	}
	credFile := j.agent.Store.CredentialFile
	var old []byte
	if !j.missing {
		if old, err = os.ReadFile(credFile); err != nil {
			return RunAnswer{}, refuse(CodeSetupFailed, "This engine cannot read the agent's credential, so it cannot tell which database is the agent's. Nothing changed.")
		}
	}
	conn, err := s.connect(ctx, j.req.DatabaseURL)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var database string
	wrote := false
	err = inTx(ctx, conn, func(tx pgx.Tx) error {
		if database, err = s.fixDatabase(ctx, tx, j); err != nil {
			return err
		}
		script, _, err := s.repairPlan(j, password)
		if err != nil {
			return err
		}
		if err := setuprun.ApplyInitTx(ctx, tx, script); err != nil {
			return refuse(CodeSetupFailed, fmt.Sprintf("The role %s is not a plain agent role this admin can repair (elevated attributes, other memberships, owned objects or settings it cannot reset). Nothing changed.", j.role))
		}
		wrote = true
		if err := config.WriteFile(credFile, []byte(next+"\n")); err != nil {
			return refuse(CodeSetupFailed, "This engine could not write the agent's credential; nothing changed.")
		}
		return nil
	})
	if err != nil {
		var unknown *unknownOutcomeError
		if errors.As(err, &unknown) {
			s.opts.CredentialChanged(j.req.Agent, password)
			return RunAnswer{}, refuse(CodeSetupFailed, "The database did not confirm the setup. Run it again on this page: it finishes if the setup went through, and starts over if it did not.")
		}
		switch {
		case wrote && j.missing:
			_ = os.Remove(credFile) // the role keeps its old password
		case wrote:
			_ = config.WriteFile(credFile, old) // the role keeps its old password
		}
		return RunAnswer{}, timeLimit(ctx, AsRefusal(err))
	}
	s.opts.CredentialChanged(j.req.Agent, password)
	return RunAnswer{
		Agent: j.req.Agent, Lines: []string{fmt.Sprintf("new password set for %s in the database %s", j.role, database)},
		Warnings: []string{}, Passkeys: []RegisteredPasskey{}, MCPCommand: "basalt mcp --agent " + j.req.Agent,
	}, nil
}

// newCredential is the agent's credential with password in place of its
// old one: everything else stays, the user name too (a pooler's is
// role.<ref>). With the file gone it is made from the admin string, as the
// install makes it. On a host this engine pins the credential uses
// sslmode=verify-full with no sslrootcert, so the pin applies.
func (s *Service) newCredential(j agentJob, dsn, password string) (string, error) {
	var out string
	if j.missing {
		made, err := s.be.AgentConnString(j.req.DatabaseURL, j.role, password)
		if err != nil {
			return "", refuse(CodeConnectionStringRefused, "The admin connection string must be a postgres:// URL with the admin's user and password, the host and the database, as your provider shows it.")
		}
		out = made
	} else {
		u, err := url.Parse(dsn)
		if err != nil || u.Host == "" || u.User == nil || u.User.Username() == "" {
			return "", refuse(CodeSetupFailed, "The agent's credential on this computer is not one this engine wrote. Nothing changed.")
		}
		u.User = url.UserPassword(u.User.Username(), password)
		out = u.String()
	}
	if host, _, ok := hostPort(out); ok {
		if p := s.opts.Profiles().For(host); p != nil && p.Name == trustprofile.PinName(host) {
			out = withVerifyFull(out)
		}
	}
	return out, nil
}
