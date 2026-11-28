package setup

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The decisions of basalt init --remote (CONTRACT.md, basalt init --remote):
// which code a run makes, whether a pending one is printed again, what the
// code carries and what the person reads. The CLI (setupcli) finds the facts
// (the config, the credential files, the agent's login) and writes the
// results; these functions read only the facts they are given.

// RemoteRun is what one basalt init --remote run found.
type RemoteRun struct {
	// Agent is the agent's name, Prefix its role prefix and Timeout its
	// statement timeout.
	Agent   string
	Prefix  string
	Timeout time.Duration
	// Entry is the agent's entry in engine.json, nil when it has none.
	Entry *config.Agent
	// Password is the agent's password this machine holds for the
	// database, "" when it holds none.
	Password string
	// LoggedIn: the role logs in with the credential. Recorded: the
	// pending setup is recorded in its database. Installed is the guard
	// version the login sees.
	LoggedIn, Recorded bool
	Installed          int
	// Latest is the guard version this build installs.
	Latest int
	// CertChanged: the login failed on the certificate of the agent's
	// pinned host, which presents another chain top.
	CertChanged bool
	// ConnectOnly: no credential file, so the code is connect-only.
	ConnectOnly bool
	// Target is the database the credential names (not connect-only).
	Target setupcode.Target
}

// Reusable is the pending setup init prints again: unexpired at now and not
// yet run.
func (r RemoteRun) Reusable(now time.Time) *config.Setup {
	if r.Entry == nil || r.Entry.Setup == nil || r.Recorded || r.Password == "" || r.Entry.Setup.CertificateChanged != r.CertChanged {
		return nil
	}
	if r.Entry.Setup.ConnectOnly() || ConnectOnlyCode(r.Entry.Setup.Code) {
		// A connect-only code with a credential file is never handed out
		// again on this path: the engine stopped between writing the
		// credential and clearing awaitingAddress, or the person confirmed
		// a database that does not record the setup (SETUP_NOT_FOUND). The
		// credential's own code replaces it.
		return nil
	}
	s := r.Entry.Setup
	expires, err := s.Expires()
	if err != nil || !now.Before(expires) {
		return nil
	}
	return s
}

// Decide picks the kind (CONTRACT.md, basalt init --remote, item 3; RI-6).
// A changed certificate of the agent's pinned host: an UPGRADE code marked
// certificateChanged, never a new password. A role that does not log in
// while an INSTALL setup is pending: INSTALL again with the password this
// machine holds, so any of its INSTALL codes matches the credential. A role
// that does not log in otherwise: the database refuses the credential
// (CREDENTIAL_REJECTED), so an AGENT code with a new password (RI-17), with
// no flag. A role that logs in while a connect-only setup the person
// confirmed is not recorded there (SETUP_NOT_FOUND: it ran in another
// database of the same server): an AGENT code with a new password for this
// one. Otherwise AGENT for an agent the config does not have yet; else
// UPGRADE when its guard is older than this build's; else an AGENT code
// with no change. Every AGENT code names no tables: the role keeps its
// grants (Payload).
func (r RemoteRun) Decide() (Plan, error) {
	if r.CertChanged {
		return Plan{Kind: setupcode.KindUpgrade}, nil
	}
	pendingInstall := r.Entry != nil && r.Entry.Setup != nil && r.Entry.Setup.Kind == string(setupcode.KindInstall)
	if !r.LoggedIn {
		switch {
		case r.Password != "" && pendingInstall:
			return Plan{Kind: setupcode.KindInstall, Password: r.Password, Rotate: true}, nil
		case r.Password != "":
			return WithNewPassword(Plan{Kind: setupcode.KindAgent})
		}
		return WithNewPassword(Plan{Kind: setupcode.KindInstall})
	}
	if r.Installed > r.Latest {
		return Plan{}, fmt.Errorf("the database's guard (version %d) is newer than this basalt (version %d): update basalt on this machine first", r.Installed, r.Latest)
	}
	p := Plan{From: r.Installed}
	switch {
	case r.ConfirmedNotFound():
		p.Kind = setupcode.KindAgent
		return WithNewPassword(p)
	case r.Entry == nil:
		p.Kind = setupcode.KindAgent
	case r.Installed < r.Latest:
		p.Kind = setupcode.KindUpgrade
	default:
		p.Kind = setupcode.KindAgent
	}
	return p, nil
}

// ConfirmedNotFound reports whether the pending setup is a connect-only
// code whose database the person confirmed and that the database the agent
// logs in to does not record (the engine's SETUP_NOT_FOUND).
func (r RemoteRun) ConfirmedNotFound() bool {
	s := r.Entry
	return s != nil && s.Setup != nil && !s.Setup.ConnectOnly() && ConnectOnlyCode(s.Setup.Code) && !r.Recorded
}

// WithNewPassword is p with a new password, which the code's verifier
// carries and the run writes.
func WithNewPassword(p Plan) (Plan, error) {
	pw, err := setupcode.NewPassword()
	if err != nil {
		return Plan{}, err
	}
	p.Password, p.Rotate, p.NewPassword = pw, true, true
	return p, nil
}

// PendingConnectOnly is the agent's pending connect-only setup, nil when
// none: waiting for its address, or refused by the person.
func (r RemoteRun) PendingConnectOnly() *config.Setup {
	if r.Entry == nil || r.Entry.Setup == nil || !r.Entry.Setup.ConnectOnly() {
		return nil
	}
	return r.Entry.Setup
}

// ConnectOnlyPlan is the plan of a new connect-only code: INSTALL, or AGENT
// in place of a pending connect-only setup (a recovery code), always with a
// new password.
func (r RemoteRun) ConnectOnlyPlan() (Plan, error) {
	kind := setupcode.KindInstall
	if r.PendingConnectOnly() != nil {
		kind = setupcode.KindAgent
	}
	return WithNewPassword(Plan{Kind: kind})
}

// ConnectOnlyAllowed is nil when a run may make a connect-only code for an
// engine with settings, written over prev (existed: there was a config):
// the engine is agent-operated with the Vault on (init --remote always
// writes the portal's pages). Otherwise the message names what the connect
// page needs.
func ConnectOnlyAllowed(settings config.Settings, prev config.Config, existed bool) error {
	if settings.OperatedBy != mcpcontract.OperatedByAgent {
		return errors.New("this engine is person-operated, and basalt init --remote sets up only an agent-operated engine: " +
			"the person runs basalt init on this machine instead")
	}
	if settings.VaultFor(prev, existed).Vault != config.VaultOn {
		return errors.New("this engine has the Vault off, and the connect page that basalt init --remote hands the person needs it on")
	}
	return nil
}

// Payload builds the setup code's content for p, with a setup id from rand
// at now. engine is the engine's key for the code and pin the engine's pin
// for the host; each is asked for only when the code carries it (not on a
// connect-only code; the pin not on an INSTALL).
func (r RemoteRun) Payload(p Plan, now time.Time, rand io.Reader, engine func() *setupcode.Engine, pin func() string) (setupcode.Payload, error) {
	id, expires, err := setupcode.NewSetupID(now, rand)
	if err != nil {
		return setupcode.Payload{}, err
	}
	out := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: p.Kind, Prefix: r.Prefix,
		Guard: setupcode.Guard{From: p.From, To: r.Latest}, Build: BuildVersion(), ExpiresAt: expires,
	}
	if !r.ConnectOnly {
		target := r.Target
		out.Target, out.Engine = &target, engine()
		if p.Kind != setupcode.KindInstall {
			// The engine's pin for the host, a hint for the connect page.
			out.TrustPin = pin()
		}
	}
	if r.CertChanged && out.Engine == nil {
		return setupcode.Payload{}, ErrNoEngineForTrust
	}
	if p.Kind == setupcode.KindUpgrade {
		return out, nil
	}
	// An INSTALL code asks for every table in public, which the person
	// ticks on the connect page. An AGENT code names no tables: the role
	// keeps the grants it holds (CONTRACT.md, The setup code, Kinds), and
	// a role that is gone runs as an INSTALL, with ticks.
	a := &setupcode.Agent{Name: r.Agent, StatementTimeoutMs: r.Timeout.Milliseconds()}
	if p.Kind == setupcode.KindInstall {
		a.AllTables = &setupcode.AllTables{Schemas: []string{"public"}}
	}
	if p.Rotate {
		if a.Verifier, err = setupcode.NewVerifier(p.Password); err != nil {
			return setupcode.Payload{}, err
		}
	}
	out.Agent = a
	return out, nil
}

// RemoteResult is the result of the code s (reused: printed again): the
// code, and what the person does with it. connectBudget is the link budget
// for the connect link, 0 when the engine hands none. The OS user and the
// basalt mcp command are the CLI's to add.
func (r RemoteRun) RemoteResult(s config.Setup, reused bool, connectBudget int) RemoteInitResult {
	res := RemoteInitResult{
		Agent: r.Agent, SetupID: s.SetupID, Kind: s.Kind, Code: s.Code, Fingerprint: s.Fingerprint,
		Reused: reused, ExpiresAt: s.ExpiresAt, PersonMessage: SetupPersonMessage(r.Agent, s.Fingerprint),
	}
	if s.AwaitingAddress {
		return r.connectOnlyResult(res, s, connectBudget)
	}
	return r.withSetupGuidance(res, s, connectBudget)
}

// withSetupGuidance is the person message and connect link of a code that
// is not connect-only.
func (r RemoteRun) withSetupGuidance(res RemoteInitResult, s config.Setup, connectBudget int) RemoteInitResult {
	// An agent-operated engine with the Vault on hands the connect link
	// when the whole link fits the budget (no network call: the link only
	// holds the code); else the text says where to paste the code.
	url := guidance.ConnectLink(s.Code, connectBudget)
	if url != "" {
		res.ConnectURL = url
		res.PersonMessage, _ = guidance.ConnectMessage("Finish setting up BasaltDB for "+r.Agent+".", url, s.Fingerprint)
	}
	res.PasteAtPortal = url == ""
	return res
}

// connectOnlyResult is the result of a connect-only code: the connect link
// and the fingerprint. A link over the budget is left
// out: the text says to paste the code at the connect page.
func (r RemoteRun) connectOnlyResult(res RemoteInitResult, s config.Setup, connectBudget int) RemoteInitResult {
	res.ConnectOnly = true
	lead := "Connect your database to " + r.Agent + "."
	if open := guidance.ConnectLink(s.Code, connectBudget); open != "" {
		res.ConnectURL = open
		res.PersonMessage, _ = guidance.ConnectOnlyMessage(lead, open, s.Fingerprint)
		return res
	}
	res.PasteAtPortal = true
	page := strings.TrimPrefix(links.Portal+links.ConnectPath, "https://")
	res.PersonMessage = lead + " Open " + page + ", paste the setup code the agent shows you, check that it shows the setup fingerprint " + s.Fingerprint +
		", and follow the page. The page asks for your database's connection string: paste it there only. The agent never needs it, so never paste it into this chat."
	return res
}

// SetupPersonMessage is what the agent shows the person verbatim, within
// guidance.MaxPersonMessageLength for the longest agent name: it names the
// agent once.
func SetupPersonMessage(name, fingerprint string) string {
	return fmt.Sprintf("Finish setting up BasaltDB for %s: open %s, paste the setup code the agent shows you, "+
		"check that it shows the setup fingerprint %s, and follow the page. "+
		"The page asks for your database's connection string: paste it there only, never into this chat.",
		name, strings.TrimPrefix(links.Portal+links.ConnectPath, "https://"), fingerprint)
}
