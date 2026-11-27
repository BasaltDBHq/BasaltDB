package setup

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// A certificate not checked (CONTRACT.md, The Update check): the agent's
// connection is encrypted, but its sslmode is below verify-full, so nothing
// checks that the certificate is its database's; or it is not encrypted at
// all (sslmode=disable, or prefer and allow on a server without TLS).
// BasaltDB keeps the sslmode a person gave; the check-up shows a warning
// row, and the TRUST fix turns the check on with the person's click: the
// agent's connection string gets sslmode=verify-full once a login with it
// passed.

// The doctor's certificate rows for an agent connection below verify-full:
// encrypted with the certificate not checked, or not encrypted.
const (
	StateNotChecked   = "NOT_CHECKED"
	StateNotEncrypted = "NOT_ENCRYPTED"
)

// sslModeDefault is the driver's sslmode for a string that names none.
const sslModeDefault = "prefer"

// unchecked is an agent's credential whose certificate is not checked.
type unchecked struct {
	dsn  string
	host string
	port int
	// mode is the sslmode the credential names, prefer for none.
	mode string
	// provider is the provider whose built-in roots cover host, "" for none.
	provider string
}

// uncheckedCredential reads the agent's credential and reports whether it
// connects below verify-full: any sslmode but verify-full, disable and
// allow included. A credential that names its own roots, or one this engine
// cannot read, is not this case.
func (s *LocalService) uncheckedCredential(a config.Agent) (unchecked, bool) {
	dsn, err := s.be.ReadCredential(a.Store.CredentialFile)
	if err != nil {
		return unchecked{}, false
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return unchecked{}, false
	}
	q := u.Query()
	mode := q.Get(paramSSLMode)
	if q.Has("sslrootcert") {
		return unchecked{}, false
	}
	applied, err := s.be.ExplainTrust(dsn, s.opts.Profiles())
	if err != nil || applied.Applies != trustprofile.AppliesNotVerified {
		return unchecked{}, false
	}
	host, port, ok := hostPort(dsn)
	if !ok {
		return unchecked{}, false
	}
	if mode == "" {
		mode = sslModeDefault
	}
	return unchecked{dsn: dsn, host: host, port: port, mode: mode, provider: trustprofile.BuiltInProvider(host, s.opts.Profiles())}, true
}

// certificateNotChecked sets the doctor's certificate row when the agent's
// credential is below verify-full, by the TLS of its login on conn, as
// status's warnings read it: NOT_CHECKED with TLS, NOT_ENCRYPTED without
// (prefer on a server without TLS falls back to none). A warning: the page
// still says Ready.
func (s *LocalService) certificateNotChecked(conn Conn, a config.Agent, out *DoctorAnswer) {
	uc, ok := s.uncheckedCredential(a)
	if !ok {
		return
	}
	state := StateNotChecked
	if shown, _ := s.be.ConnCertificate(conn, certNotVerified, ""); shown != certNotVerified {
		if loopbackHost(uc.host) {
			return // no TLS, but the connection never leaves this machine
		}
		state = StateNotEncrypted // no TLS on this connection
	}
	out.Certificate = DoctorCertificate{State: state, Host: uc.host, Port: uc.port, SSLMode: uc.mode, Provider: uc.provider}
}

// loopbackHost reports whether host is this machine (localhost,
// 127.0.0.0/8, ::1), whose plaintext connection is not warned about, as
// status's CONNECTION_NOT_ENCRYPTED skips it.
func loopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// verifiedCredential is the agent's credential with sslmode=verify-full,
// once a login with it as the agent's role passed: the certificate checks
// out (pgx sends the startup message only after the handshake verified),
// and the role still logs in. A certificate that does not verify refuses
// with nothing sent.
func (s *LocalService) verifiedCredential(ctx context.Context, j agentJob, uc unchecked) (string, error) {
	next := withVerifyFull(uc.dsn)
	conn, err := s.opts.Dial(ctx, next)
	switch {
	case err == nil:
	case s.be.CertificateNotVerified(err):
		who := uc.host
		if uc.provider != "" {
			who = uc.provider
		}
		return "", refuse(CodeCertificateNotVerified, fmt.Sprintf("This database's certificate didn't match %s's, so nothing was sent. The agent keeps sslmode=%s; nothing changed.", who, uc.mode))
	case loginRefused(err):
		return "", refuse(CodeLoginFailed, "The database refused the agent's login with the certificate check on. Nothing changed.")
	default:
		return "", timeLimit(ctx, refuse(CodeDatabaseUnreachable, "The database could not be reached with the certificate check on. Nothing changed."))
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if user, err := s.be.CurrentUser(ctx, conn.Port()); err != nil || user != j.role {
		return "", refuse(CodeSetupFailed, "The agent's credential with the certificate check on does not log in as its role. Nothing changed.")
	}
	return next, nil
}

// checkPlan is the TRUST fix's answer for a certificate not checked.
func (s *LocalService) checkPlan(j agentJob, uc unchecked, database string) CheckAnswer {
	return fixAnswer(database, []string{
		fmt.Sprintf("This turns on the certificate check for %s: its connection to %s changes from sslmode=%s to sslmode=verify-full. Nothing changes in the database.", j.req.Agent, uc.host, uc.mode),
	}, "-- nothing runs in the database: the agent's connection string on this computer gets sslmode=verify-full\n")
}

// checkUnchecked logs in with the admin string, makes the checks every fix
// makes, then tries the agent's credential with sslmode=verify-full.
func (s *LocalService) checkUnchecked(ctx context.Context, j agentJob, uc unchecked) (CheckAnswer, error) {
	database, err := s.uncheckedChecks(ctx, j)
	if err != nil {
		return CheckAnswer{}, err
	}
	if _, err := s.verifiedCredential(ctx, j, uc); err != nil {
		return CheckAnswer{}, err
	}
	return s.checkPlan(j, uc, database), nil
}

// runUnchecked repeats the check, then writes the agent's credential with
// sslmode=verify-full and has the engine serve its config again, so the
// agent's connections check the certificate from now on. Nothing changes in
// the database.
func (s *LocalService) runUnchecked(ctx context.Context, j agentJob, uc unchecked) (RunAnswer, error) {
	database, err := s.uncheckedChecks(ctx, j)
	if err != nil {
		return RunAnswer{}, err
	}
	next, err := s.verifiedCredential(ctx, j, uc)
	if err != nil {
		return RunAnswer{}, err
	}
	if err := s.be.WriteFile(j.agent.Store.CredentialFile, []byte(next+"\n")); err != nil {
		return RunAnswer{}, refuse(CodeSetupFailed, "This engine could not write the agent's credential; nothing changed.")
	}
	s.opts.Reload()
	return RunAnswer{
		Agent:    j.req.Agent,
		Lines:    []string{fmt.Sprintf("%s now checks the certificate of %s (sslmode=verify-full), in the database %s", j.req.Agent, uc.host, database)},
		Warnings: []string{}, Passkeys: []RegisteredPasskey{},
	}, nil
}

// uncheckedChecks makes, with the admin string, the checks every fix makes
// before it changes anything, in a transaction it rolls back.
func (s *LocalService) uncheckedChecks(ctx context.Context, j agentJob) (string, error) {
	conn, err := s.connect(ctx, j.req.DatabaseURL)
	if err != nil {
		return "", err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return "", s.setupFailed("begin", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	database, err := s.fixDatabase(ctx, tx, j)
	return database, timeLimit(ctx, err)
}
