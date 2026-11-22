package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// defaultPGPort is Postgres's port when a connection string names none.
const defaultPGPort = 5432

// fetchChain reads the chain host:port presents with the TLS handshake
// alone (trustpin.Fetch); cliIO.fetchChain outside tests.
func fetchChain(ctx context.Context, host string, port int) ([]*x509.Certificate, error) {
	return trustpin.Fetch(ctx, nil, host, port)
}

// pinTarget is the host and port a pin is for.
type pinTarget struct {
	host string
	port int
}

// targetOf is the first host and port of a postgres:// URL, or false for a
// Unix socket or a string without a host.
func targetOf(dsn string) (pinTarget, bool) {
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() == "" || strings.HasPrefix(u.Query().Get(paramHost), "/") {
		return pinTarget{}, false
	}
	host := strings.Split(u.Host, ",")[0]
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h, p = strings.Trim(host, "[]"), ""
	}
	port := defaultPGPort
	if p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return pinTarget{}, false
		}
	}
	return pinTarget{host: trustprofile.NormalizeHost(h), port: port}, true
}

// pinChoice is a chain top the person accepted for a host.
type pinChoice struct {
	pinTarget
	top    *x509.Certificate
	sha256 string
	caOnly bool
}

// errPinDeclined: the person did not say yes.
var errPinDeclined = errors.New("not pinned")

// errAgentPin: an agent runs this, so nothing is pinned.
var errAgentPin = errors.New("an agent never pins a certificate")

// errPublicPin: the certificate is, or chains to, an authority the system
// trusts and failed on the name: nothing is pinned (CONTRACT.md, Pinning on
// first use, Public authorities).
var errPublicPin = errors.New("no pin for a public authority's certificate")

// errNoPinNeeded: the host's certificate verifies already, or a profile
// covers the host.
var errNoPinNeeded = errors.New("no pin needed")

// askPin reads the chain t presents, with nothing but the TLS handshake,
// and when it verifies neither against the system's authorities nor a
// profile, shows its top certificate and asks the person whether to trust
// it for t.host alone (default no). trustRoot, when set, answers for a run
// without a terminal: it must be the top's SHA-256 exactly. Without a
// terminal and without it, the usage error names the flag and the
// fingerprint seen. Under an agent marker or on an engine operatedBy AGENT
// it pins nothing (refuseAgentTrust): an agent never creates trust.
func (c *cliIO) askPin(t pinTarget, trustRoot, configPath string, agentOperated bool) (pinChoice, error) {
	if c.fetchChain == nil {
		return pinChoice{}, errNoPinNeeded
	}
	if p := trustdir.Set(configPath).For(t.host); p != nil {
		return pinChoice{}, errNoPinNeeded
	}
	chain, err := c.fetchChain(c.ctx, t.host, t.port)
	if err != nil {
		return pinChoice{}, fmt.Errorf("the certificate of %s cannot be read: %w", t.host, err)
	}
	seen := trustpin.Check(chain, t.host, c.now())
	if seen.System {
		return pinChoice{}, errNoPinNeeded
	}
	if seen.Public {
		return pinChoice{}, fmt.Errorf("%w: the certificate %s presents comes from an authority this machine already trusts, "+
			"but it does not verify for %s, so it failed on the name; a pin would trust everything that authority issues, so none is made. "+
			"Connect with the host name the certificate names", errPublicPin, t.host, t.host)
	}
	if !seen.Full && !seen.NameOnly {
		return pinChoice{}, fmt.Errorf("the certificate chain %s presents does not verify even against its own top certificate "+
			"(expired, not valid for a server, or not sent whole), so it cannot be pinned; name its CA with sslrootcert in the connection string", t.host)
	}
	if agentOperated {
		return pinChoice{}, fmt.Errorf("%w: the engine is operatedBy AGENT", errAgentPin)
	}
	if err := c.refuseAgentTrust(configPath); err != nil {
		return pinChoice{}, fmt.Errorf("%w: %w", errAgentPin, err)
	}
	c.showChainTop(t, seen)
	choice := pinChoice{pinTarget: t, top: seen.Top, sha256: seen.SHA256, caOnly: seen.NameOnly}
	if trustRoot != "" {
		want, err := trustprofile.NormalizeSHA256(trustRoot)
		if err != nil {
			return pinChoice{}, fmt.Errorf("%w: --trust-root: %w", errUsage, err)
		}
		if want != seen.SHA256 {
			return pinChoice{}, fmt.Errorf("%w: --trust-root %s is not the certificate %s presents (SHA-256 %s); nothing was pinned",
				errUsage, trustRoot, t.host, trustprofile.Fingerprint(seen.Top))
		}
		return choice, nil
	}
	if !c.interactive {
		return pinChoice{}, fmt.Errorf("%w: the certificate of %s verifies against no authority this machine trusts, and input is not a terminal, "+
			"so basalt cannot ask whether to trust it; check the fingerprint against your provider's console and pass --trust-root %s",
			errUsage, t.host, seen.SHA256)
	}
	question := fmt.Sprintf("Trust this certificate authority for %s only?", t.host)
	if seen.NameOnly {
		question = fmt.Sprintf("Trust this certificate authority for %s only, with the host name not checked?", t.host)
	}
	ok, err := c.confirm(question)
	if err != nil || !ok {
		return pinChoice{}, errPinDeclined
	}
	return choice, nil
}

// showChainTop prints the host and the chain's top certificate: subject,
// SHA-256 and expiry, and for a name-only chain why the name is not
// checked.
func (c *cliIO) showChainTop(t pinTarget, seen trustpin.Seen) {
	fmt.Fprintf(c.stderr, "basalt: %s presents a certificate that verifies against no authority this machine trusts.\n", terminalText(t.host))
	fmt.Fprintf(c.stderr, "  Subject:  %s\n  SHA-256:  %s\n  Expires:  %s\n", terminalText(seen.Top.Subject.String()),
		trustprofile.Fingerprint(seen.Top), seen.Top.NotAfter.UTC().Format(time.DateOnly))
	fmt.Fprintln(c.stderr, "  Check the fingerprint against your database provider's console before you trust it.")
	if seen.NameOnly {
		fmt.Fprintf(c.stderr, "  Its certificate does not name %s, so the full check failed on the name alone: pinned, the chain must end at this "+
			"certificate, and the host name is not checked (verify: ca).\n", terminalText(t.host))
	}
}

// writePin writes choice as configPath's pin and makes this process's
// connections trust it from now on.
func (c *cliIO) writePin(choice pinChoice, configPath string) error {
	_, replaced, err := trustdir.Pin(configPath, choice.host, choice.top, choice.caOnly)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) && c.host.Euid() != 0 {
			return fmt.Errorf("%w; trust.d belongs to the engine's user: run it with sudo", err)
		}
		return err
	}
	pgdial.SetTrust(trustdir.Source(configPath))
	fmt.Fprintf(c.stderr, "basalt: pinned %s for %s in %s\n", trustprofile.Fingerprint(choice.top), choice.host, trustdir.Path(configPath))
	for _, old := range replaced {
		if old != choice.sha256 {
			fmt.Fprintf(c.stderr, "basalt: it replaces the pinned certificate with SHA-256 %s\n", old)
		}
	}
	return nil
}

// pinCommand is the basalt trust pin command the person runs for t.
func pinCommand(t pinTarget) string {
	return "basalt trust pin --host " + shellQuote(t.host) + " --port " + strconv.Itoa(t.port)
}

// refuseAgentTrust refuses a pin when an agent marker is set or the engine
// is operatedBy AGENT: an agent never adds a root. An engine.json that
// exists and cannot be read is refused too.
func (c *cliIO) refuseAgentTrust(configPath string) error {
	if marker := c.agentMarker(); marker != "" {
		return fmt.Errorf("the pin is refused: %s is set, so an agent is running it, and an agent never changes which root certificates "+
			"are trusted. Nothing was written. The person trusts it on the page basalt init opens", marker)
	}
	cfg, err := loadEngineConfig(c, configPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("the pin is refused: %s cannot be read (%w), so whether an agent operates this engine is not known. Nothing was written", configPath, err)
	case cfg.AgentOperated():
		return fmt.Errorf("the pin is refused: this engine is operatedBy AGENT, so an agent could have run it, and an agent never changes which " +
			"root certificates are trusted. Nothing was written. Name the root in the agent's connection string with sslrootcert instead")
	}
	return nil
}

// initPin is the pin an init offers for dsn's host before anything else
// reaches the server: the choice and true, or false when none is needed,
// it is declined, or it cannot be made (an agent runs init, the chain
// cannot be read): init then goes on as before. A usage error (no terminal
// and no --trust-root, or one that does not match) ends init.
func (c *cliIO) initPin(dsn, trustRoot, configPath string, agentOperated bool) (pinChoice, bool, error) {
	t, ok := targetOf(dsn)
	if !ok || namesOwnRoots(dsn) {
		if trustRoot != "" {
			return pinChoice{}, false, fmt.Errorf("%w: --trust-root is given, but the connection string names its own roots "+
				"(sslrootcert) or does not use TLS, so no pin applies", errUsage)
		}
		return pinChoice{}, false, nil
	}
	choice, err := c.askPin(t, trustRoot, configPath, agentOperated)
	switch {
	case err == nil:
		return choice, true, nil
	case errors.Is(err, errNoPinNeeded):
		if trustRoot != "" {
			return pinChoice{}, false, fmt.Errorf("%w: --trust-root is given, but %s needs no pin: its certificate verifies already", errUsage, t.host)
		}
	case errors.Is(err, errPublicPin) && trustRoot != "":
		return pinChoice{}, false, fmt.Errorf("%w: --trust-root is refused: %w", errUsage, err)
	case errors.Is(err, errPublicPin):
		fmt.Fprintf(c.stderr, "basalt: %s\n", terminalText(err.Error()))
	case errors.Is(err, errPinDeclined):
		fmt.Fprintf(c.stderr, "basalt: nothing pinned for %s; its certificate is not verified\n", terminalText(t.host))
	case errors.Is(err, errAgentPin) && trustRoot != "":
		return pinChoice{}, false, fmt.Errorf("%w: --trust-root is refused: an agent never pins a certificate; the person runs %s",
			errUsage, pinCommand(t))
	case errors.Is(err, errAgentPin):
		fmt.Fprintf(c.stderr, "basalt: %s presents a certificate no authority here verifies, and an agent never pins one. "+
			"The person checks it and pins it on this machine:\n  %s\n", terminalText(t.host), pinCommand(t))
	case errors.Is(err, errUsage):
		return pinChoice{}, false, err
	}
	// Otherwise the chain cannot be read (no route, no TLS): nothing to
	// offer, and the probes and the connection that follow say what is wrong.
	return pinChoice{}, false, nil
}

// codeTrustRootChanged starts the error of a connection to a pinned host
// that presents another root.
const codeTrustRootChanged = "TRUST_ROOT_CHANGED"

// rootChanged is TRUST_ROOT_CHANGED for err, a certificate of dsn's host
// that did not verify, when that host is pinned and the chain top it
// presents now (read with the TLS handshake alone) is not the pinned one:
// both fingerprints and where the new one is accepted. Nil
// otherwise. Never accepted automatically.
func rootChanged(ctx context.Context, dsn string, err error) error {
	return rootChangedVia(ctx, dsn, err, nil)
}

// rootChangedVia is rootChanged reaching the host through dial (nil: the
// network).
func rootChangedVia(ctx context.Context, dsn string, err error, dial trustpin.Dial) error {
	if !pgdial.CertificateNotVerified(err) {
		return nil
	}
	cfg, perr := pgconn.ParseConfig(dsn)
	if perr != nil {
		return nil //nolint:nilerr // a string pgx cannot parse has no pinned host to compare
	}
	a := trustprofile.Explain(cfg, pgdial.Trust())
	host := trustprofile.NormalizeHost(cfg.Host)
	if a.Profile == nil || a.Profile.Name != trustprofile.PinName(host) {
		return nil
	}
	chain, ferr := trustpin.Fetch(ctx, dial, host, int(cfg.Port))
	if ferr != nil {
		return nil //nolint:nilerr // the chain cannot be read now: the certificate error is said as it is
	}
	top := chain[len(chain)-1]
	pinnedTo := make([]string, 0, len(a.Profile.Certificates()))
	for _, c := range a.Profile.Certificates() {
		if trustprofile.DERSHA256(c) == trustprofile.DERSHA256(top) {
			return nil
		}
		pinnedTo = append(pinnedTo, trustprofile.Fingerprint(c))
	}
	return fmt.Errorf("%w; %s: %s presents the certificate authority SHA-256 %s, but it is pinned to %s. Check it against your "+
		"provider's console; to accept it, run basalt init (basalt init --remote on an agent-operated engine) and trust it on the page it opens",
		err, codeTrustRootChanged, host, trustprofile.Fingerprint(top), strings.Join(pinnedTo, ", "))
}

// namesOwnRoots reports whether dsn names its own roots (sslrootcert,
// PGSSLROOTCERT, ~/.postgresql/root.crt) or uses no TLS: no profile, and so
// no pin, applies to it.
func namesOwnRoots(dsn string) bool {
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return false
	}
	return cfg.TLSConfig == nil || cfg.TLSConfig.RootCAs != nil
}
