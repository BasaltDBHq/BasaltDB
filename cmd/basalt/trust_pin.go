package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/internal/trustpin"
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
func (c *cliIO) askPin(t pinTarget, trustRoot, configPath, repinning string, agentOperated bool) (pinChoice, error) {
	if c.fetchChain == nil {
		return pinChoice{}, errNoPinNeeded
	}
	set := trustdir.Set(configPath)
	if repinning != "" {
		set = withoutProfile(set, repinning)
	}
	if p := set.For(t.host); p != nil {
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
	if !seen.Full && !seen.NameOnly {
		return pinChoice{}, fmt.Errorf("the certificate chain %s presents does not verify even against its own top certificate "+
			"(expired, not valid for a server, or not sent whole), so it cannot be pinned; name its CA with sslrootcert in the connection string", t.host)
	}
	if agentOperated {
		return pinChoice{}, fmt.Errorf("%w: the engine is operatedBy AGENT", errAgentPin)
	}
	if err := c.refuseAgentTrust("pin", configPath); err != nil {
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
		return trustWriteError(c, "pin", err)
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
func pinCommand(t pinTarget, configPath string, goos string) string {
	cmd := "basalt trust pin --host " + shellQuote(t.host) + " --port " + strconv.Itoa(t.port)
	if configPath != config.DefaultPath(goos) {
		cmd += " --config " + shellQuote(configPath)
	}
	return cmd
}

// trustPin is basalt trust pin --host H [--port P] [--trust-root SHA256].
func trustPin(c *cliIO, args []string) int {
	fs := c.flags("trust pin")
	configPath := fs.String("config", config.DefaultPath(c.goos), "engine config file; the pin goes in its trust.d")
	host := fs.String("host", "", "the database host to pin, as the connection string names it")
	port := fs.Int("port", defaultPGPort, "the database port")
	trustRoot := fs.String("trust-root", "", "without a terminal: the SHA-256 of the certificate to pin, which must match what the server presents")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	*configPath = configOrFallback(c.host, fs, *configPath)
	if *host == "" {
		return c.fail(fmt.Errorf("%w: --host is required: basalt trust pin --host H [--port P]", errUsage))
	}
	t := pinTarget{host: trustprofile.NormalizeHost(*host), port: *port}
	choice, err := c.askPin(t, *trustRoot, *configPath, c.repin(t, *configPath), false)
	switch {
	case errors.Is(err, errNoPinNeeded):
		fmt.Fprintf(c.stdout, "basalt: %s needs no pin: its certificate verifies already\n", t.host)
		return exitOK
	case errors.Is(err, errPinDeclined):
		return c.fail(errors.New("you did not confirm; nothing was pinned"))
	case err != nil:
		return c.fail(err)
	}
	if err := c.writePin(choice, *configPath); err != nil {
		return c.fail(err)
	}
	fmt.Fprintln(c.stderr, "basalt: the engine uses it from its next connection; no restart is needed")
	return exitOK
}

// repin, when t.host already has a pin, shows it and names it, so askPin
// leaves it out and asks about what the server presents now: a new root
// after TRUST_ROOT_CHANGED. Nothing is written until the yes. "" when the
// host has no pin.
func (c *cliIO) repin(t pinTarget, configPath string) string {
	p := trustdir.Set(configPath).For(t.host)
	if p == nil || !p.Exact() || p.Name != trustprofile.PinName(t.host) {
		return ""
	}
	fmt.Fprintf(c.stderr, "basalt: %s is pinned to:\n", terminalText(t.host))
	printRoots(c.stderr, p.Certificates())
	return p.Name
}

// withoutProfile is set without the operator profile name.
func withoutProfile(set *trustprofile.Set, name string) *trustprofile.Set {
	return replacing(set, name, nil)
}

// replacing is set with the operator profile name left out and add, when
// not nil, in its place.
func replacing(set *trustprofile.Set, name string, add *trustprofile.Profile) *trustprofile.Set {
	var ops, builtin []*trustprofile.Profile
	for _, l := range set.Profiles() {
		switch {
		case l.Origin == trustprofile.Operator && l.Name == name:
		case l.Origin == trustprofile.Operator:
			ops = append(ops, l.Profile)
		default:
			builtin = append(builtin, l.Profile)
		}
	}
	if add != nil {
		ops = append(ops, add)
	}
	return trustprofile.NewSet(builtin, ops, set.Refused())
}

// trustRootFlag adds --trust-root to fs.
func trustRootFlag(fs *flag.FlagSet) *string {
	return fs.String("trust-root", "", "without a terminal: the SHA-256 of the certificate authority to pin for a database whose certificate "+
		"verifies against no authority this machine trusts; it must match what the server presents")
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
	choice, err := c.askPin(t, trustRoot, configPath, "", agentOperated)
	switch {
	case err == nil:
		return choice, true, nil
	case errors.Is(err, errNoPinNeeded):
		if trustRoot != "" {
			return pinChoice{}, false, fmt.Errorf("%w: --trust-root is given, but %s needs no pin: its certificate verifies already", errUsage, t.host)
		}
	case errors.Is(err, errPinDeclined):
		fmt.Fprintf(c.stderr, "basalt: nothing pinned for %s; its certificate is not verified\n", terminalText(t.host))
	case errors.Is(err, errAgentPin) && trustRoot != "":
		return pinChoice{}, false, fmt.Errorf("%w: --trust-root is refused: an agent never pins a certificate; the person runs %s",
			errUsage, pinCommand(t, configPath, c.goos))
	case errors.Is(err, errAgentPin):
		fmt.Fprintf(c.stderr, "basalt: %s presents a certificate no authority here verifies, and an agent never pins one. "+
			"The person checks it and pins it on this machine:\n  %s\n", terminalText(t.host), pinCommand(t, configPath, c.goos))
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
// both fingerprints and the command that accepts the new one. Nil
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
		"provider's console; to accept it run: basalt trust pin --host %s --port %d", err, codeTrustRootChanged, host,
		trustprofile.Fingerprint(top), strings.Join(pinnedTo, ", "), shellQuote(host), cfg.Port)
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

// trustInMemory makes this process's connections trust choice for its
// host, without writing it, and returns admin with sslmode=verify-full: the
// admin connection then verifies against the certificate the person just
// accepted before it sends the admin's login (verify: ca, the chain only,
// for a name-only pin).
func (c *cliIO) trustInMemory(choice pinChoice, admin, configPath string) (string, error) {
	p, err := trustdir.PinProfile(choice.host, choice.top, choice.caOnly)
	if err != nil {
		return "", err
	}
	pgdial.SetTrust(func() *trustprofile.Set { return replacing(trustdir.Set(configPath), p.Name, p) })
	return withVerifyFull(admin), nil
}
