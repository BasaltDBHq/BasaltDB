// Package connecttest is a small test server for basalt.connect.v1.SetupService
// (CONTRACT.md, Connect), built on the public setup package and the generated
// ConnectRPC handler. Tests use it to drive the three calls the connect page
// makes against a real Postgres. It is not part of the binary: only test
// files import it.
//
// It follows the contract's calls, order of refusals and refusal reasons,
// the address hand-off and the reach check included (the hold in its
// PREVIEW and SET_UP phases, the ticket, CollectAddress, ReportReach,
// HandoffStatus and OfferAddress). It differs from the hosted service in
// what is not the setup's own logic: it dials the pasted string as given,
// or through Options.Dial (the hosted service requires verified TLS and
// refuses private addresses), and it has no limits.
package connecttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// ChallengeLife is how long a passkey challenge lives (the contract's 15
// minutes).
const ChallengeLife = 15 * time.Minute

// OpenGrace is how long after expiresAt CheckSetup and RunSetup still take
// a code the page opened while it was live (the contract's 30 minutes, the
// grace record_setup also allows).
const OpenGrace = 30 * time.Minute

// maxPasskeyLabel is the longest passkey picker label, in bytes.
const maxPasskeyLabel = 64

var b64 = base64.RawURLEncoding

// Server is the service. Its zero value is not usable: use Start.
type Server struct {
	skew   atomic.Int64 // nanoseconds the service's clock is ahead
	secret []byte
	holds  holds
	// opened maps each code DescribeSetup answered (spaces removed) to its
	// expiresAt.
	openedMu sync.Mutex
	opened   map[string]time.Time
	dial     func(ctx context.Context, url string) (*pgx.Conn, error)
	// collectsRefused and reportsRefused count the CollectAddress and
	// ReportReach calls answered HANDOFF_UNKNOWN.
	collectsRefused, reportsRefused atomic.Int64
}

// Options change how the service reaches the pasted database (tests whose
// database sits behind a test TLS proxy).
type Options struct {
	// Dial opens the admin connection for a pasted string; nil dials it as
	// given.
	Dial func(ctx context.Context, url string) (*pgx.Conn, error)
}

// Start serves a Server on a local test server until the test ends and
// returns the base URL a client posts to (the calls are at
// <base>/basalt.connect.v1.SetupService/<Method>).
func Start(t *testing.T) (*Server, string) {
	t.Helper()
	return StartWith(t, Options{})
}

// StartWith is Start with o.
func StartWith(t *testing.T, o Options) (*Server, string) {
	t.Helper()
	s := &Server{secret: make([]byte, 32), dial: o.Dial}
	if s.dial == nil {
		s.dial = dial
	}
	if _, err := rand.Read(s.secret); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(connectv1connect.NewSetupServiceHandler(s))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return s, ts.URL
}

var _ connectv1connect.SetupServiceHandler = (*Server)(nil)

// Advance moves the service's clock forward, to age a code or a challenge.
func (s *Server) Advance(d time.Duration) { s.skew.Add(int64(d)) }

// Now is the service's clock.
func (s *Server) Now() time.Time { return time.Now().Add(time.Duration(s.skew.Load())) }

// request is a setup request as the connect service makes it: a
// connect-only code is accepted (ConnectPage).
func (s *Server) request(code string) setup.Request {
	return setup.Request{Code: code, Now: s.Now(), ConnectPage: true}
}

// afterOpen is the request for CheckSetup and RunSetup: a code the page
// opened while live is checked with a clock just before its expiresAt for
// OpenGrace after it, so a confirmed run may finish late.
func (s *Server) afterOpen(code string) setup.Request {
	req := s.request(code)
	s.openedMu.Lock()
	exp, ok := s.opened[strings.Join(strings.Fields(code), "")]
	s.openedMu.Unlock()
	if ok && !req.Now.Before(exp) && !req.Now.After(exp.Add(OpenGrace)) {
		req.Now = exp.Add(-time.Nanosecond)
	}
	return req
}

func (s *Server) noteOpen(code string, expires time.Time) {
	s.openedMu.Lock()
	defer s.openedMu.Unlock()
	if s.opened == nil {
		s.opened = map[string]time.Time{}
	}
	s.opened[strings.Join(strings.Fields(code), "")] = expires
}

// DescribeSetup is the call that needs no database.
func (s *Server) DescribeSetup(_ context.Context, r *connect.Request[connectv1.DescribeSetupRequest]) (*connect.Response[connectv1.DescribeSetupResponse], error) {
	d, err := setup.Describe(s.request(r.Msg.GetCode()))
	if err != nil {
		return nil, refuse(err)
	}
	s.noteOpen(r.Msg.GetCode(), d.ExpiresAt)
	ch := PasskeyChallenge{Challenge: make([]byte, 32), UserID: make([]byte, 16)}
	for _, b := range [][]byte{ch.Challenge, ch.UserID} {
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
	}
	// The picker's label names the database, or the agent's role for a
	// connect-only code, whose database is not known yet.
	label := d.AgentRole
	if d.Target != nil {
		label = d.Target.Database
	}
	ch.UserName = label
	ch.DisplayName = "BasaltDB · " + label
	if len(ch.DisplayName) > maxPasskeyLabel {
		ch.DisplayName = label
	}
	ch.ExpiresAt = s.Now().Add(ChallengeLife).UTC().Format(time.RFC3339)
	ch.MAC = s.mac(ch, d.Fingerprint)
	return connect.NewResponse(&connectv1.DescribeSetupResponse{Summary: summary(d), Challenge: ch.proto()}), nil
}

// CheckSetup connects and reads.
func (s *Server) CheckSetup(ctx context.Context, r *connect.Request[connectv1.CheckSetupRequest]) (*connect.Response[connectv1.CheckSetupResponse], error) {
	conn, err := s.dial(ctx, r.Msg.GetDatabaseUrl())
	if err != nil {
		return nil, refuse(err)
	}
	defer conn.Close(ctx)
	req := s.afterOpen(r.Msg.GetCode())
	c, err := setup.Check(ctx, conn, req)
	var se *setup.Error
	if errors.As(err, &se) && se.Code == codeUsed {
		// A connect-only code that ran in this database may run again
		// (the recovery path): alreadyRan, and the page skips the tables
		// and the labels. A SET_UP hold of another database is refused
		// USED as before.
		if d, derr := setup.Describe(req); derr == nil && d.Target == nil {
			at := setup.ConnDatabase(conn.Config())
			if !s.otherTarget(d, at) {
				return connect.NewResponse(&connectv1.CheckSetupResponse{Database: target(at), AlreadyRan: true}), nil
			}
		}
	}
	if err != nil {
		return nil, refuse(err)
	}
	out := &connectv1.CheckSetupResponse{
		PasskeyNeeded: c.PasskeyNeeded, NothingToDo: c.NothingToDo != nil, Database: target(c.Database), Tables: slices.Clone(c.Tables),
	}
	for _, e := range c.Excluded {
		out.Excluded = append(out.Excluded, &connectv1.ExcludedTable{Table: e.Table, Owner: e.Owner})
	}
	out.ReadOnly = slices.Clone(c.ReadOnly)
	for _, l := range c.Columns {
		out.Columns = append(out.Columns, &connectv1.ColumnLabel{Table: l.Table, Column: l.Column, Class: l.Class, EntityType: l.EntityType, PhoneRegion: l.PhoneRegion})
	}
	if c.NothingToDo == nil {
		out.Notes = notes(c)
	}
	for _, q := range c.Questions.RowSecurity {
		out.Questions = append(out.Questions, &connectv1.Question{
			Kind: rowSecurity, Table: q.Table, Text: q.Text, Choices: []string{choiceAllRows, choiceNone},
		})
	}
	// The reach check: a connect-only INSTALL code that logged in and is
	// not refused gets a PREVIEW hold of the pasted database, unless a
	// SET_UP hold exists.
	if c.Description.Target == nil && c.Description.Kind == setup.KindInstall {
		if out.Ticket, err = s.previewFor(c.Description, c.Database); err != nil {
			return nil, err
		}
	}
	return connect.NewResponse(out), nil
}

// codeUsed is the setup package's refusal of a code the database already
// ran.
const codeUsed = "USED"

const (
	rowSecurity   = "ROW_LEVEL_SECURITY"
	choiceAllRows = "ALL_ROWS"
	choiceNone    = "NONE"
)

// RunSetup connects and runs the setup in one transaction. Like the
// contract, it checks the challenge and the passkey before it connects.
func (s *Server) RunSetup(ctx context.Context, r *connect.Request[connectv1.RunSetupRequest]) (*connect.Response[connectv1.RunSetupResponse], error) {
	m := r.Msg
	req := s.afterOpen(m.GetCode())
	// The page's ticks: every RunSetup sends them (empty for a code
	// without ticks), so pkg/setup checks them for every code.
	req.Included = &setup.Included{Tables: m.GetIncludedTables()}
	d, err := setup.Describe(req)
	if err != nil {
		return nil, refuse(err)
	}
	var reg *registration
	if m.GetPasskey() != nil {
		if reg, err = s.verifyPasskey(m, d); err != nil {
			return nil, err
		}
	}
	conn, err := s.dial(ctx, m.GetDatabaseUrl())
	if err != nil {
		return nil, refuse(err)
	}
	defer conn.Close(ctx)
	// After the login to the pasted database succeeded: only someone who
	// can log in to a database learns that the code ran elsewhere.
	at := setup.ConnDatabase(conn.Config())
	if d.Target == nil && s.otherTarget(d, at) {
		return nil, refusal(connect.CodeFailedPrecondition, "RUN_ELSEWHERE", runElsewhere)
	}
	checked, err := setup.Check(ctx, conn, req)
	var se *setup.Error
	if d.Target == nil && errors.As(err, &se) && se.Code == codeUsed {
		// The same connect-only code again in the database it ran in: the
		// address is held again, nothing changes.
		ticket, terr := s.holdFor(d, at)
		if terr != nil {
			return nil, terr
		}
		return connect.NewResponse(&connectv1.RunSetupResponse{Ticket: ticket, Reconnected: true}), nil
	}
	if err != nil {
		return nil, refuse(err)
	}
	var in setup.RunInput
	if checked.NothingToDo == nil {
		if in.Answers.AllRows, err = answers(checked.Questions, m.GetAnswers()); err != nil {
			return nil, err
		}
		if checked.PasskeyNeeded && reg == nil {
			return nil, refusal(connect.CodeFailedPrecondition, "PASSKEY_REQUIRED", "A passkey is needed for this setup.")
		}
	} else if len(m.GetAnswers()) > 0 {
		return nil, refusal(connect.CodeInvalidArgument, "ANSWERS_INVALID", "This setup asks no questions.")
	}
	if reg != nil {
		in.Passkey = &reg.verified // registered in the setup's transaction
	}
	in.RestPublic = m.GetRestPublic()
	for _, c := range m.GetColumnClasses() {
		w := c.GetWas()
		in.ColumnClasses = append(in.ColumnClasses, setup.ColumnClass{
			Table: c.GetTable(), Column: c.GetColumn(),
			Label: setup.Label{Class: c.GetClass(), EntityType: c.GetEntityType(), PhoneRegion: c.GetPhoneRegion()},
			Was:   setup.Label{Class: w.GetClass(), EntityType: w.GetEntityType(), PhoneRegion: w.GetPhoneRegion()},
		})
	}
	res, err := setup.Run(ctx, conn, req, in)
	if err != nil {
		return nil, refuse(err)
	}
	out := &connectv1.RunSetupResponse{Warnings: res.Warnings, NothingToDo: res.NothingToDo != nil}
	if d.Target == nil {
		if out.Ticket, err = s.holdFor(d, at); err != nil {
			return nil, err
		}
	}
	if res.Passkey != nil && reg != nil {
		out.Passkeys = []*connectv1.RegisteredPasskey{{
			CredentialId: b64.EncodeToString(res.Passkey.CredentialID), Label: res.Passkey.Label, CheckCode: reg.checkCode,
		}}
	}
	return connect.NewResponse(out), nil
}

type registration struct {
	verified  setup.Passkey
	checkCode string
}

// verifyPasskey is the contract's challenge and registration checks, before
// any connection: the mac against the challenge's fields and the fingerprint
// of the code in this request, the expiry, then the registration itself.
func (s *Server) verifyPasskey(m *connectv1.RunSetupRequest, d setup.Description) (*registration, error) {
	ch, err := challengeOf(m.GetChallenge())
	if err != nil || !hmac.Equal([]byte(ch.MAC), []byte(s.mac(ch, d.Fingerprint))) {
		return nil, refusal(connect.CodeInvalidArgument, "CHALLENGE_INVALID", "The passkey challenge is not valid for this setup. Start again from the link.")
	}
	if exp, err := time.Parse(time.RFC3339, ch.ExpiresAt); err != nil || !s.Now().Before(exp) {
		return nil, refusal(connect.CodeInvalidArgument, "CHALLENGE_EXPIRED", "The passkey challenge expired. Start again from the link.")
	}
	pk := m.GetPasskey()
	resp := passkey.RegistrationResponse{PublicKeyAlgorithm: int(pk.GetPublicKeyAlgorithm()), PRFSupported: pk.GetPrfSupported()}
	for _, f := range []struct {
		in  string
		out *passkey.Bytes
	}{
		{pk.GetCredentialId(), &resp.CredentialID},
		{pk.GetClientDataJson(), &resp.ClientDataJSON},
		{pk.GetAuthenticatorData(), &resp.AuthenticatorData},
		{pk.GetPublicKey(), &resp.PublicKey},
	} {
		raw, err := b64.DecodeString(f.in)
		if err != nil {
			return nil, refusal(connect.CodeInvalidArgument, "PASSKEY_INVALID", "The passkey was not accepted.")
		}
		*f.out = raw
	}
	code, err := resp.Code()
	if err != nil {
		return nil, refusal(connect.CodeInvalidArgument, "PASSKEY_INVALID", "The passkey was not accepted.")
	}
	label := pk.GetLabel()
	if label == "" {
		label = ch.UserName
	}
	req, err := setup.PasskeyRequestFor(setup.PasskeyChallenge{
		Challenge: ch.Challenge, UserID: ch.UserID, UserName: ch.UserName, DisplayName: ch.DisplayName,
	}, label)
	if err != nil {
		return nil, refusal(connect.CodeInvalidArgument, "CHALLENGE_INVALID", "The passkey challenge is not valid for this setup. Start again from the link.")
	}
	verified, err := req.Verify(code)
	if err != nil {
		return nil, refusal(connect.CodeInvalidArgument, "PASSKEY_INVALID", "The passkey was not accepted.")
	}
	check, err := checkCode(resp.PublicKey)
	if err != nil {
		return nil, refusal(connect.CodeInvalidArgument, "PASSKEY_INVALID", "The passkey was not accepted.")
	}
	return &registration{verified: verified, checkCode: check}, nil
}

// checkCode is the passkey check code of an SPKI P-256 key.
func checkCode(spki []byte) (string, error) {
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return "", err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("not an EC key")
	}
	raw, err := pub.Bytes() // 0x04 || X || Y
	if err != nil || len(raw) != 65 {
		return "", errors.New("not a P-256 key")
	}
	return passkey.CheckCode(raw[1:33], raw[33:]), nil
}

// answers turns the page's answers into the setup's, refusing one to a
// question that was not asked and a question left unanswered
// (ANSWERS_INVALID), as the contract says RunSetup does.
func answers(q setup.Questions, got []*connectv1.Answer) ([]string, error) {
	invalid := func() error {
		return refusal(connect.CodeInvalidArgument, "ANSWERS_INVALID", "The answers do not match the questions for this database.")
	}
	asked := map[string]bool{}
	for _, rq := range q.RowSecurity {
		asked[rq.Table] = false
	}
	var all []string
	for _, a := range got {
		answered, ok := asked[a.GetTable()]
		if a.GetKind() != rowSecurity || !ok || answered {
			return nil, invalid()
		}
		switch a.GetChoice() {
		case choiceAllRows:
			all = append(all, a.GetTable())
		case choiceNone:
		default:
			return nil, invalid()
		}
		asked[a.GetTable()] = true
	}
	for _, answered := range asked {
		if !answered {
			return nil, invalid()
		}
	}
	return all, nil
}

func notes(c setup.Checked) []string {
	out := make([]string, 0, len(c.Summary)+len(c.EngineLines)+len(c.Questions.OutsidePublic))
	out = append(out, c.Summary...)
	out = append(out, c.EngineLines...)
	for _, t := range c.Questions.OutsidePublic {
		out = append(out, t+" is outside schema public.")
	}
	return out
}

func summary(d setup.Description) *connectv1.SetupSummary {
	out := &connectv1.SetupSummary{
		SetupId: d.SetupID, Kind: string(d.Kind), Agent: d.Agent, Role: d.AgentRole, Prefix: d.Prefix,
		Write: slices.Clone(d.Write), Read: slices.Clone(d.Read), AllTablesSchemas: slices.Clone(d.AllTablesSchemas),
		StatementTimeoutMs: int32(d.StatementTimeoutMs), GuardFrom: int32(d.GuardFrom), GuardTo: int32(d.GuardTo),
		ExpiresAt: d.ExpiresAt.UTC().Format(time.RFC3339), Fingerprint: d.Fingerprint,
		EngineFingerprint: d.EngineFingerprint, Lines: slices.Clone(d.Summary),
	}
	if d.Target != nil {
		out.Target = target(*d.Target)
	}
	return out
}

func target(t setup.Target) *connectv1.Target {
	return &connectv1.Target{Host: t.Host, Port: int32(t.Port), Database: t.Database, SupabaseRef: t.SupabaseRef}
}

// PasskeyChallenge is the decoded challenge.
type PasskeyChallenge struct {
	Challenge, UserID                []byte
	UserName, DisplayName, ExpiresAt string
	MAC                              string
}

func (c PasskeyChallenge) proto() *connectv1.PasskeyChallenge {
	return &connectv1.PasskeyChallenge{
		Challenge: b64.EncodeToString(c.Challenge), UserId: b64.EncodeToString(c.UserID),
		UserName: c.UserName, DisplayName: c.DisplayName, ExpiresAt: c.ExpiresAt, Mac: c.MAC,
	}
}

func challengeOf(p *connectv1.PasskeyChallenge) (PasskeyChallenge, error) {
	if p == nil {
		return PasskeyChallenge{}, errors.New("no challenge")
	}
	c, err := b64.DecodeString(p.GetChallenge())
	if err != nil {
		return PasskeyChallenge{}, err
	}
	u, err := b64.DecodeString(p.GetUserId())
	if err != nil {
		return PasskeyChallenge{}, err
	}
	return PasskeyChallenge{Challenge: c, UserID: u, UserName: p.GetUserName(), DisplayName: p.GetDisplayName(), ExpiresAt: p.GetExpiresAt(), MAC: p.GetMac()}, nil
}

// mac is a keyed hash over every field of the challenge and the code's
// fingerprint.
func (s *Server) mac(c PasskeyChallenge, fingerprint string) string {
	h := hmac.New(sha256.New, s.secret)
	for _, f := range []string{b64.EncodeToString(c.Challenge), b64.EncodeToString(c.UserID), c.UserName, c.DisplayName, c.ExpiresAt, fingerprint} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return b64.EncodeToString(h.Sum(nil))
}

// dial opens the admin connection the way basalt does behind a pooler.
func dial(ctx context.Context, url string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, &refusalError{connect.CodeInvalidArgument, "CONNECTION_STRING_REFUSED", "The connection string is not one this service accepts."}
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && (pe.Code == "28P01" || pe.Code == "28000") {
			return nil, &refusalError{connect.CodeFailedPrecondition, "LOGIN_FAILED", "The database refused the login."}
		}
		return nil, &refusalError{connect.CodeUnavailable, "DATABASE_UNREACHABLE", "Could not connect to the database."}
	}
	return conn, nil
}

type refusalError struct {
	code    connect.Code
	reason  string
	message string
}

func (e *refusalError) Error() string { return e.message }

func refusal(code connect.Code, reason, message string) error {
	return refuse(&refusalError{code, reason, message})
}

// refuse is a ConnectRPC error whose detail is a Refusal. Messages are fixed
// words: the setup package's own sentences for a refusal of the code, and one
// fixed sentence for the database's or driver's failures.
func refuse(err error) error {
	var re *refusalError
	var se *setup.Error
	switch {
	case errors.As(err, &re):
	case errors.As(err, &se):
		re = fromSetup(se)
	default:
		re = &refusalError{connect.CodeFailedPrecondition, "SETUP_FAILED", "The setup failed and nothing changed."}
	}
	ce := connect.NewError(re.code, errors.New(re.message))
	if d, derr := connect.NewErrorDetail(&connectv1.Refusal{Reason: re.reason, Message: re.message}); derr == nil {
		ce.AddDetail(d)
	}
	return ce
}

func fromSetup(e *setup.Error) *refusalError {
	switch e.Code {
	case "NOT_A_SETUP_CODE", "INVALID", "UNSUPPORTED_FORMAT", "DAMAGED", "EXPIRED", "SETUP_ID_IN_FUTURE", "EXPIRY_TOO_FAR", "GUARD_TOO_OLD":
		return &refusalError{connect.CodeInvalidArgument, e.Code, e.Message}
	case "BINARY_TOO_OLD":
		return &refusalError{connect.CodeUnavailable, e.Code, "Basalt Vault is being updated: try again shortly, or use the laptop command."}
	case setup.CodeTargetMismatch, "PREFIX_MISMATCH", codeUsed, "SUPERSEDED", "ROLE_EXISTS", "ROLE_MISSING", setup.CodeEngineRevoked, setup.CodeTablesMissing,
		setup.CodeNoTables, setup.CodeTablesChanged, setup.CodeClassesChanged:
		return &refusalError{connect.CodeFailedPrecondition, e.Code, e.Message}
	case setup.CodeAnswersInvalid:
		return &refusalError{connect.CodeInvalidArgument, e.Code, "The answers do not match the questions for this database."}
	case setup.CodePasskeyRequired:
		return &refusalError{connect.CodeFailedPrecondition, e.Code, "A passkey is needed for this setup."}
	case setup.CodePasskeyInvalid:
		return &refusalError{connect.CodeInvalidArgument, e.Code, "The passkey was not accepted."}
	}
	return &refusalError{connect.CodeFailedPrecondition, "SETUP_FAILED", "The setup failed and nothing changed."}
}
