package localsetup

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/lib/pgquerier"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
)

// The Update check (CONTRACT.md, The Update check): doctor reads, with the
// agent's own credential and the engine's own state, what needs the
// person. It takes no admin connection string, reads metadata only and
// changes nothing. While the database's certificate changed, or the agent
// cannot log in, it reads nothing from the database.

// DoctorRequest is the body of the doctor route.
type DoctorRequest struct {
	Agent  string `json:"agent"`
	OSUser string `json:"osUser"`
}

// States of the doctor's rows.
const (
	StateOK        = "OK"
	StateUnknown   = "UNKNOWN"
	StateCurrent   = "CURRENT"
	StateOutdated  = "OUTDATED"
	StateNewer     = "NEWER"
	StateMissing   = "MISSING"
	StateChanged   = "CHANGED"
	StateMismatch  = "MISMATCH"
	StateUnlabeled = "UNLABELED"
	StateNone      = "NONE"
)

const (
	// maxDoctorColumns is how many unlabeled column names doctor names.
	maxDoctorColumns = 20
)

// DoctorAnswer is the doctor route's answer.
type DoctorAnswer struct {
	// Database is current_database() as the agent reads it, "" when the
	// engine could not log in.
	Database    string            `json:"database,omitempty"`
	Guard       DoctorGuard       `json:"guard"`
	Certificate DoctorCertificate `json:"certificate"`
	Login       *DoctorLogin      `json:"login,omitempty"`
	Labels      DoctorLabels      `json:"labels"`
	Passkeys    DoctorPasskeys    `json:"passkeys"`
}

// DoctorGuard is the guard as status reads it. From and To are set on
// OUTDATED. UNKNOWN when it was not read.
type DoctorGuard struct {
	State string `json:"state"`
	From  int    `json:"from,omitempty"`
	To    int    `json:"to,omitempty"`
}

// DoctorCertificate is the database certificate as status reads it.
// CHANGED carries the host, the pinned SHA-256 and what the host presents;
// MISMATCH the host, the engine's pin and the ledger's.
type DoctorCertificate struct {
	State     string     `json:"state"`
	Host      string     `json:"host,omitempty"`
	Port      int        `json:"port,omitempty"`
	Pinned    string     `json:"pinned,omitempty"`
	Presented *TrustRoot `json:"presented,omitempty"`
	Recorded  string     `json:"recorded,omitempty"`
	// PinnedSubject and Database are CHANGED's for the confirm step: the
	// subject of the pinned certificate, read from its PEM file in
	// trust.d, and the database the agent's credential names (doctor
	// reads nothing from the database then).
	PinnedSubject string `json:"pinnedSubject,omitempty"`
	Database      string `json:"database,omitempty"`
	// SameIssuer is CHANGED's: the presented top has the public key of the
	// pinned certificate, or the pinned certificate signed it (sameIssuer).
	SameIssuer bool `json:"sameIssuer"`
}

// DoctorLogin is why the agent could not log in: status's problem code and
// a fixed message.
type DoctorLogin struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// DoctorLabels are the columns the agent's role reads that have no label.
type DoctorLabels struct {
	State   string   `json:"state"`
	Count   int      `json:"count"`
	Columns []string `json:"columns"`
}

// DoctorPasskeys are the database's active passkeys.
type DoctorPasskeys struct {
	State string          `json:"state"`
	Items []DoctorPasskey `json:"items"`
}

// DoctorPasskey is one active passkey's public data. Origin is where it
// signs, so the page can name another site's.
type DoctorPasskey struct {
	CredentialID string     `json:"credentialId"`
	Label        string     `json:"label"`
	RPID         string     `json:"rpId"`
	Origin       string     `json:"origin"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastUsedAt   *time.Time `json:"lastUsedAt,omitempty"`
}

// Doctor is the Update check for an agent of this engine. It is not a
// setup run: it does not take the run lock.
func (s *Service) Doctor(ctx context.Context, req DoctorRequest) (DoctorAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, callLimit)
	defer cancel()
	if !s.opts.Configured {
		return DoctorAnswer{}, refuse(CodeJobUnavailable, "This engine has no config yet, so it has no agent to check. Ask the agent for a new link.")
	}
	if err := s.engineRemoved(); err != nil {
		return DoctorAnswer{}, err
	}
	a, _, err := s.configuredAgent(req.Agent, req.OSUser)
	if err != nil {
		return DoctorAnswer{}, err
	}
	out := DoctorAnswer{
		Guard: DoctorGuard{State: StateUnknown}, Certificate: DoctorCertificate{State: StateOK},
		Labels:   DoctorLabels{State: StateUnknown, Columns: []string{}},
		Passkeys: DoctorPasskeys{State: StateUnknown, Items: []DoctorPasskey{}},
	}
	conn, err := s.agentLogin(ctx, a, &out)
	switch {
	case errors.Is(err, errNoLogin):
		return out, nil
	case err != nil:
		return DoctorAnswer{}, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if err := s.readDoctor(ctx, conn, a, &out); err != nil {
		return DoctorAnswer{}, timeLimit(ctx, setupFailed("read the doctor checks", err))
	}
	return out, nil
}

// errNoLogin: agentLogin set on the answer why the agent cannot log in.
var errNoLogin = errors.New("the agent cannot log in")

// agentLogin logs in with the agent's credential, or sets why it could
// not on out and returns errNoLogin. A certificate that does not verify
// is never answered with a login: the chain is read with the handshake
// alone, and a pinned host presenting another chain top is CHANGED.
func (s *Service) agentLogin(ctx context.Context, a config.Agent, out *DoctorAnswer) (*pgx.Conn, error) {
	rejected := &DoctorLogin{Code: action.ReasonCredentialRejected, Message: "The database refuses the agent's credential, or this engine has none for it."}
	dsn, err := s.be.ReadCredential(a.Store.CredentialFile)
	if err != nil {
		out.Login = rejected
		return nil, errNoLogin
	}
	conn, err := s.opts.Dial(ctx, dsn)
	if err == nil {
		return conn, nil
	}
	var pg *pgconn.PgError
	switch {
	case ctx.Err() != nil:
		return nil, refuse(CodeTimeLimit, "The check ran out of time.")
	case s.be.CertificateNotVerified(err):
		if s.certificateChanged(ctx, a, out) {
			return nil, errNoLogin
		}
		out.Login = &DoctorLogin{Code: CodeCertificateNotVerified, Message: "The database's TLS certificate does not verify, so the agent cannot connect."}
	case errors.As(err, &pg) && len(pg.Code) >= 2 && pg.Code[:2] == "28":
		out.Login = rejected
	default:
		out.Login = &DoctorLogin{Code: action.ReasonDatabaseUnreachable, Message: "The database cannot be reached with the agent's credential."}
	}
	return nil, errNoLogin
}

// certificateChanged sets CHANGED when the agent's host is pinned and
// presents another chain top, read with the TLS handshake alone.
func (s *Service) certificateChanged(ctx context.Context, a config.Agent, out *DoctorAnswer) bool {
	h, err := s.hostOf(a)
	if err != nil || h.pin == nil {
		return false
	}
	chain, err := s.opts.Probe(ctx, h.host, h.port)
	if err != nil || len(chain) == 0 {
		return false
	}
	seen := trustpin.Check(chain, h.host, s.opts.Now())
	if pinHolds(h.pin, seen.SHA256) {
		return false
	}
	out.Certificate = DoctorCertificate{
		State: StateChanged, Host: h.host, Port: h.port, Pinned: pinnedSHA(h.pin, ""), Presented: presentedRoot(seen),
		PinnedSubject: pinnedSubject(h.pin, ""), Database: h.database, SameIssuer: sameIssuer(h.pin, seen.Top),
	}
	return true
}

// readDoctor reads, on the agent's connection, metadata only: the
// database's name, the guard, the ledger's pin, the unlabeled columns and
// the passkeys. A row that cannot be read stays UNKNOWN.
func (s *Service) readDoctor(ctx context.Context, conn *pgx.Conn, a config.Agent, out *DoctorAnswer) error {
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.current_database()::text`).Scan(&out.Database); err != nil {
		return err
	}
	st, err := s.be.AgentStatus(ctx, pgquerier.Neutralize(conn), s.be.Migrations())
	if err != nil {
		return err
	}
	out.Guard = s.guardRow(st)
	if out.Guard.State == StateMissing {
		return nil
	}
	if h, err := s.hostOf(a); err == nil && h.pin != nil {
		if rec, ok, err := s.be.RecordedTrustPin(ctx, pgquerier.Neutralize(conn), h.host, h.port); err == nil && ok && !pinHolds(h.pin, rec) {
			out.Certificate = DoctorCertificate{State: StateMismatch, Host: h.host, Port: h.port, Pinned: pinnedSHA(h.pin, ""), Recorded: rec}
		}
	}
	out.Labels = s.doctorLabels(ctx, conn)
	out.Passkeys = s.doctorPasskeys(ctx, conn)
	return nil
}

// guardRow is the guard by the test UPDATE makes: OUTDATED exactly when an
// UPDATE has migrations to add.
func (s *Service) guardRow(st guardmodel.Status) DoctorGuard {
	latest := s.be.LatestVersion()
	switch {
	case st.State == guardmodel.GuardMissing || st.Installed == 0:
		return DoctorGuard{State: StateMissing}
	case st.Installed > latest:
		return DoctorGuard{State: StateNewer}
	case st.Installed < latest:
		return DoctorGuard{State: StateOutdated, From: st.Installed, To: latest}
	}
	return DoctorGuard{State: StateCurrent}
}

// doctorLabels counts the columns pii_unclassified() returns for the
// agent's role with why NEW or UNCLASSIFIED, and names the first 20.
func (s *Service) doctorLabels(ctx context.Context, conn *pgx.Conn) DoctorLabels {
	out := DoctorLabels{State: StateUnknown, Columns: []string{}}
	cols, err := s.be.PIIUnclassified(ctx, pgquerier.Neutralize(conn))
	if err != nil {
		return out
	}
	for _, c := range cols {
		if !c.Unclassified() {
			continue
		}
		out.Count++
		if len(out.Columns) < maxDoctorColumns {
			out.Columns = append(out.Columns, c.Name())
		}
	}
	out.State = StateOK
	if out.Count > 0 {
		out.State = StateUnlabeled
	}
	return out
}

// doctorPasskeys lists the active passkeys the agent's role may read
// (agent_passkeys), at most 100, oldest first. OK when one has this page's
// origin.
func (s *Service) doctorPasskeys(ctx context.Context, conn *pgx.Conn) DoctorPasskeys {
	out := DoctorPasskeys{State: StateUnknown, Items: []DoctorPasskey{}}
	keys, err := s.be.ListPasskeys(ctx, pgquerier.Neutralize(conn))
	if err != nil {
		return out
	}
	out.State = StateNone
	for _, k := range keys {
		c := k.Credential
		if c.Relying.Origin == s.opts.Origin {
			out.State = StateOK
		}
		out.Items = append(out.Items, DoctorPasskey{
			CredentialID: base64.RawURLEncoding.EncodeToString(c.ID), Label: k.Label, RPID: c.Relying.RPID,
			Origin: c.Relying.Origin, CreatedAt: k.CreatedAt.UTC(), LastUsedAt: utcPtr(k.LastUsedAt),
		})
	}
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
