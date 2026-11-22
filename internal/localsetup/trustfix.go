package localsetup

import (
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// TRUST: the certificate (CONTRACT.md, The Update check). The engine pins
// the agent's database host; the fix either replaces the pin with the new
// certificate the person trusted (CHANGED), or records the engine's pin in
// the ledger when the ledger names another (MISMATCH). Nothing is sent to
// a server before the engine has read its chain with the handshake alone.

// agentHost is the agent's database host and port as status reads them:
// the first host of its credential, normalized as the trust profiles match
// it, so the record the fix makes is the one status looks up.
type agentHost struct {
	host string
	port int
	// database is the database the agent's credential names.
	database string
	// pin is this engine's pin for host, nil when it has none.
	pin *trustprofile.Profile
}

// hostOf reads the agent's host and this engine's pin for it.
func (s *Service) hostOf(a config.Agent) (agentHost, error) {
	dsn, err := config.ReadCredential(a.Store.CredentialFile)
	if err == nil {
		err = pgdial.CheckForeignDSN(dsn)
	}
	if err != nil {
		return agentHost{}, refuse(CodeSetupFailed, "This engine cannot read the agent's credential, so it cannot tell which database is the agent's. Nothing changed.")
	}
	pc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return agentHost{}, refuse(CodeSetupFailed, "This engine cannot read the agent's credential, so it cannot tell which database is the agent's. Nothing changed.")
	}
	h := agentHost{host: trustprofile.NormalizeHost(pc.Host), port: int(pc.Port), database: pc.Database}
	if p := s.opts.Profiles().For(h.host); p != nil && p.Name == trustprofile.PinName(h.host) {
		h.pin = p
	}
	return h, nil
}

// pinHolds: the pin holds the certificate whose DER SHA-256 is sha.
func pinHolds(p *trustprofile.Profile, sha string) bool {
	return slices.ContainsFunc(p.Certificates(), func(c *x509.Certificate) bool { return trustprofile.DERSHA256(c) == sha })
}

// pinnedSHA is the pin's certificate as one SHA-256: the one the chain
// presents when the pin holds it, else the pin's first.
func pinnedSHA(p *trustprofile.Profile, presented string) string {
	if c := pinnedCert(p, presented); c != nil {
		return trustprofile.DERSHA256(c)
	}
	return ""
}

// pinnedCert is the pin's certificate pinnedSHA names, as read from its PEM
// file in trust.d; nil for a pin with none.
func pinnedCert(p *trustprofile.Profile, presented string) *x509.Certificate {
	certs := p.Certificates()
	if i := slices.IndexFunc(certs, func(c *x509.Certificate) bool { return trustprofile.DERSHA256(c) == presented }); i >= 0 {
		return certs[i]
	}
	if len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// pinnedSubject is the subject of the certificate pinnedSHA names, as the
// install's refusal gives a subject (trustpin.SubjectOf), "" for none.
func pinnedSubject(p *trustprofile.Profile, presented string) string {
	if c := pinnedCert(p, presented); c != nil {
		return trustpin.SubjectOf(c)
	}
	return ""
}

// presentedRoot is the chain top as the page shows it for the person to
// trust: the install's refusal and doctor's presented give it the same way.
func presentedRoot(seen trustpin.Seen) *TrustRoot {
	return &TrustRoot{Subject: seen.Subject(), SHA256: seen.SHA256, ExpiresAt: seen.Top.NotAfter.UTC().Format(time.RFC3339)}
}

// trustCase is what a TRUST call found before it logged in.
type trustCase struct {
	agentHost
	seen trustpin.Seen
	// changed: the host presents another chain top than the pin.
	changed bool
	// next is the pin for the new certificate the person trusted (changed).
	next *trustprofile.Profile
}

// readTrust reads the chain the agent's host presents, with the handshake
// alone, and decides the case. A host no pin covers is NOTHING_TO_FIX.
func (s *Service) readTrust(ctx context.Context, j agentJob) (trustCase, error) {
	h, err := s.hostOf(j.agent)
	if err != nil {
		return trustCase{}, err
	}
	if h.pin == nil {
		return trustCase{}, nothingToFix()
	}
	if host, port, ok := hostPort(j.req.DatabaseURL); !ok || host != h.host || port != h.port {
		return trustCase{}, refuse(CodeTargetMismatch, "The admin connection string names another host than the agent's credential, so its certificate cannot be checked here. Use the host the agent connects to; nothing changed.")
	}
	chain, err := s.opts.Probe(ctx, h.host, h.port)
	if err != nil || len(chain) == 0 {
		return trustCase{}, timeLimit(ctx, refuse(CodeDatabaseUnreachable, "The database could not be reached. Check the host and port in the admin connection string."))
	}
	now := s.opts.Now()
	tc := trustCase{agentHost: h, seen: trustpin.Check(chain, h.host, now)}
	tc.changed = !pinHolds(h.pin, tc.seen.SHA256)
	if !tc.changed {
		// MISMATCH or nothing: the engine's pin still verifies, so nothing is
		// pinned and no trustRoot is taken.
		if j.req.TrustRoot != "" {
			return trustCase{}, refuse(CodeAnswersInvalid, "The database presents the certificate BasaltDB trusts, so there is no new one to trust. Reload the page; nothing changed.")
		}
		return tc, nil
	}
	if j.req.Pinned != "" {
		return trustCase{}, refuse(CodeAnswersInvalid, "A new certificate is trusted with its own fingerprint, not the one BasaltDB trusts now. Reload the page; nothing changed.")
	}
	if tc.seen.Public || !tc.seen.Pinnable() {
		return trustCase{}, notVerified()
	}
	if j.req.TrustRoot == "" {
		r := notVerified()
		r.TrustRoot, r.Pinned = presentedRoot(tc.seen), pinnedSHA(h.pin, "")
		return trustCase{}, r
	}
	_, next, err := trustpin.Approved(chain, h.host, now, j.req.TrustRoot)
	if err != nil {
		return trustCase{}, refuse(CodeTrustRootMismatch, "The database presents another certificate authority than the one you trusted. Nothing changed; check it again.")
	}
	tc.next = next
	return tc, nil
}

// openTrust logs in with the admin string, verify-full against that one
// certificate: the new one the person trusted, or the engine's pin.
func (s *Service) openTrust(ctx context.Context, j agentJob, tc trustCase) (*pgx.Conn, error) {
	prof := tc.pin
	if tc.changed {
		prof = tc.next
	}
	conn, err := s.opts.DialPinned(ctx, pinDSN(j.req.DatabaseURL), prof)
	if err != nil {
		r := connectError(ctx, err)
		if r.Code == CodeCertificateNotVerified {
			return nil, refuse(CodeTrustRootMismatch, "The database presents another certificate authority than the one you trusted. Nothing changed; check it again.")
		}
		return nil, r
	}
	return conn, nil
}

// trustPlan reads in tx what the fix would do, after the checks every fix
// makes: for MISMATCH the ledger's record, which must name another pin.
func (s *Service) trustPlan(ctx context.Context, tx pgx.Tx, j agentJob, tc trustCase) (CheckAnswer, error) {
	database, err := s.fixDatabase(ctx, tx, j)
	if err != nil {
		return CheckAnswer{}, err
	}
	if tc.changed {
		return fixAnswer(database, []string{fmt.Sprintf("This replaces the certificate BasaltDB trusts for %s.", tc.host)},
			recordSQL(tc.host, tc.port, tc.seen.SHA256)), nil
	}
	recorded, ok, err := guard.RecordedTrustPinTx(ctx, tx, j.names, tc.host, tc.port)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	if !ok || pinHolds(tc.pin, recorded) {
		return CheckAnswer{}, nothingToFix()
	}
	pinned := pinnedSHA(tc.pin, tc.seen.SHA256)
	out := fixAnswer(database, []string{fmt.Sprintf("This records the certificate BasaltDB trusts for %s in the ledger.", tc.host)}, recordSQL(tc.host, tc.port, pinned))
	out.Pinned, out.Recorded = pinned, recorded
	return out, nil
}

// recordSQL is the statement the fix runs, as the page shows it.
func recordSQL(host string, port int, sha string) string {
	return fmt.Sprintf("SELECT basalt_meta.record_trust_pin(%s, %d, %s);\n", guardLiteral(host), port, guardLiteral(sha))
}

// guardLiteral is s as a SQL string literal, for the shown SQL only.
func guardLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func (s *Service) checkTrust(ctx context.Context, j agentJob) (CheckAnswer, error) {
	tc, err := s.readTrust(ctx, j)
	if err != nil {
		return CheckAnswer{}, err
	}
	conn, err := s.openTrust(ctx, j, tc)
	if err != nil {
		return CheckAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return CheckAnswer{}, setupFailed()
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	out, err := s.trustPlan(ctx, tx, j, tc)
	return out, timeLimit(ctx, err)
}

// runTrust records the pin in one transaction. For a changed certificate,
// once the record succeeded and before the commit, the engine replaces its
// pin (the new PEM file, then the profile, then the old PEM file removed,
// under the config lock): a pin replaced before a commit that fails stays,
// since the person approved it and the login checked it. For a ledger that
// names another pin it writes no file, and a pin that changed since the
// login is TRUST_ROOT_MISMATCH, nothing recorded.
func (s *Service) runTrust(ctx context.Context, j agentJob) (RunAnswer, error) {
	tc, err := s.readTrust(ctx, j)
	if err != nil {
		return RunAnswer{}, err
	}
	conn, err := s.openTrust(ctx, j, tc)
	if err != nil {
		return RunAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var database, sha string
	err = inTx(ctx, conn, func(tx pgx.Tx) error {
		plan, err := s.trustPlan(ctx, tx, j, tc)
		if err != nil {
			return err
		}
		database, sha = plan.Database, tc.seen.SHA256
		if !tc.changed {
			// The pin the check showed must be the one recorded now.
			if j.req.Pinned != plan.Pinned {
				return refuse(CodeTrustRootMismatch, "The certificate BasaltDB trusts changed on this computer since the page checked it. Nothing was recorded; check it again.")
			}
			sha = plan.Pinned
		}
		if err := guard.RecordTrustPin(ctx, tx, tc.host, tc.port, sha); err != nil {
			return setupFailed()
		}
		if !tc.changed {
			now, err := s.hostOf(j.agent)
			if err != nil {
				return err
			}
			if now.pin == nil || !pinHolds(now.pin, sha) {
				return refuse(CodeTrustRootMismatch, "The certificate BasaltDB trusts changed on this computer since the page checked it. Nothing was recorded; check it again.")
			}
			return nil
		}
		if _, _, err := trustdir.Pin(s.opts.ConfigPath, tc.host, tc.seen.Top, !tc.seen.Full); err != nil {
			return refuse(CodeSetupFailed, "This engine could not replace the certificate it trusts; nothing changed.")
		}
		return nil
	})
	if err != nil {
		return RunAnswer{}, timeLimit(ctx, AsRefusal(err))
	}
	line := fmt.Sprintf("certificate SHA-256 %s recorded for %s in the database %s", sha, tc.host, database)
	if tc.changed {
		line = fmt.Sprintf("BasaltDB now trusts the certificate SHA-256 %s for %s, recorded in the database %s", sha, tc.host, database)
	}
	return RunAnswer{Agent: j.req.Agent, Lines: []string{line}, Warnings: []string{}, Passkeys: []RegisteredPasskey{}}, nil
}
