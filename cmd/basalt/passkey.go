package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/server"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// maxPasskeyLabel is the registration request's label limit in bytes.
const maxPasskeyLabel = setuprun.MaxPasskeyLabel

// relyingParty is the portal (RP ID basaltvault.app) for its origin, else
// the engine's local pages at origin (http://localhost:<port>, RP ID
// localhost), the default until hosting exists. Any other origin is refused
// (CONTRACT.md, Page origins).
func relyingParty(origin string) (passkey.Relying, error) {
	if origin == links.Portal {
		return passkey.Production, nil
	}
	rp, err := passkey.Local(origin)
	if err != nil {
		return passkey.Relying{}, fmt.Errorf("%w: --passkey-origin: %w", errUsage, err)
	}
	return rp, nil
}

// serveHint tells the person why the registration page on a local origin
// (http://localhost:<port>) is not answering: init serves it itself, so
// something else holds the port.
func serveHint(origin string) string {
	port := origin[strings.LastIndex(origin, ":")+1:]
	return fmt.Sprintf("  (port %s is taken, so basalt init cannot serve this page: stop what holds it (lsof -nP -iTCP:%s -sTCP:LISTEN), "+
		"or open the link while the engine serves the pages there)\n", port, port)
}

// defaultPasskeyLabel names a new passkey so the picker tells it apart from
// the person's other ones for the same site (every local database's pages
// are on localhost): "<database> · <agent> · <date>", the date local. A
// label past maxPasskeyLabel bytes shortens the database name, then drops
// the agent.
func defaultPasskeyLabel(db, agent string, now time.Time) string {
	const sep = " · "
	date := now.Format(time.DateOnly)
	parts := []string{db}
	if agent != "" {
		parts = append(parts, agent)
	}
	parts = append(parts, date)
	label := strings.Join(parts, sep)
	if len(label) <= maxPasskeyLabel {
		return label
	}
	rest := strings.Join(parts[1:], sep)
	room := maxPasskeyLabel - len(sep) - len(rest)
	if room < 8 && agent != "" {
		rest = date
		room = maxPasskeyLabel - len(sep) - len(rest)
	}
	return truncateUTF8(db, room) + sep + rest
}

// truncateUTF8 is s cut to at most n bytes on a character boundary, with
// "…" in place of what was cut.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	cut := n - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:max(cut, 0)] + ellipsis
}

// hasPasskeyFor reports whether an active passkey of this database belongs
// to origin (setuprun.HasPasskeyFor): an engine handed over to an agent
// needs a portal passkey of its own.
func hasPasskeyFor(c *cliIO, conn *pgx.Conn, origin string) (bool, error) {
	return setuprun.HasPasskeyFor(c.ctx, conn, origin)
}

// registerPasskey is basalt init's passkey step: print the registration
// link, read the code the page shows, verify it, and store the public key
// with the admin connection (owner decision #3; CONTRACT.md, Approvals).
func registerPasskey(c *cliIO, conn *pgx.Conn, rp passkey.Relying, label string) error {
	req, err := setuprun.NewRegistrationRequest(c.rand, label, conn.Config().Database)
	if err != nil {
		return err
	}
	// When init serves the page itself, the page posts the passkey back
	// through the hand-back route: nothing to paste.
	var hb *registrationHandBack
	if _, local := localPagesAddr(rp.Origin); local {
		if hb, err = newRegistrationHandBack(c.rand, req, rp); err != nil {
			return err
		}
	}
	stop, served := serveLocalPages(rp.Origin, hb)
	defer stop()
	if served && hb != nil {
		req = hb.req
	} else {
		hb = nil
	}
	frag, err := req.Fragment()
	if err != nil {
		return err
	}
	if err := showRegistrationLink(c, links.Register(rp.Origin)+"#"+frag, false); err != nil {
		return err
	}
	// Only a local origin is served by init, so only there can a taken
	// port explain a page that does not answer.
	if _, local := localPagesAddr(rp.Origin); local && !served {
		fmt.Fprint(c.stderr, serveHint(rp.Origin))
	}
	cred, err := readRegistration(c, req, rp, hb)
	if err != nil {
		return err
	}
	return guard.RegisterPasskey(c.ctx, conn, cred, label)
}

// showRegistrationLink prints the passkey registration link, and with
// open also opens it in the browser (basalt init --setup-code at a
// terminal).
func showRegistrationLink(c *cliIO, link string, open bool) error {
	fmt.Fprintln(c.stderr, "basalt: register the passkey that approves this agent's held writes. Open this link on your phone or computer:")
	ref := linkRef{setting: "--passkey-origin", item: "the passkey registration", again: "basalt init"}
	if err := printLink(c, c.stderr, link, ref); err != nil {
		return err
	}
	if !open {
		return nil
	}
	if err := c.host.OpenURL(c.ctx, link); err != nil {
		fmt.Fprintf(c.stderr, "basalt: could not open a browser (%v); open the link above yourself\n", err)
	}
	return nil
}

// pastedRegistrationCode reads the registration code the page shows,
// pasted by the person.
func pastedRegistrationCode(c *cliIO) (string, error) {
	fmt.Fprint(c.stderr, "Paste the code the page shows: ")
	code, err := c.pasted(c.ctx)
	if err != nil {
		return "", fmt.Errorf("no passkey code: %w", err)
	}
	return code, nil
}

// readRegistration waits for the passkey of req. Without hb it reads the
// pasted registration code. With hb (init serves the page) the page posts
// the passkey to init and shows a pairing code: init keeps only the posted
// registration whose code the person types, so a registration another
// program posted with the link is never stored. The long code pasted
// instead still registers. After maxPairingTries codes that match nothing
// it fails and nothing is stored.
func readRegistration(c *cliIO, req passkey.RegistrationRequest, rp passkey.Relying, hb *registrationHandBack) (passkey.Credential, error) {
	if hb == nil {
		code, err := pastedRegistrationCode(c)
		if err != nil {
			return passkey.Credential{}, err
		}
		return verifyRegistrationCode(code, req, rp)
	}
	fmt.Fprint(c.stderr, "basalt: Type or paste the code the page shows: ")
	full := hb.full
	for tries, readErrs := 0, 0; ; {
		line, err := readPairingLine(c, &full)
		switch {
		case err != nil && (errors.Is(err, io.EOF) || c.ctx.Err() != nil):
			return passkey.Credential{}, fmt.Errorf("no passkey code: %w", err)
		case err != nil:
			// Not a wrong code: it does not use up a try. The bound only
			// stops a terminal that fails every read.
			if readErrs++; readErrs >= maxPasteErrors {
				return passkey.Credential{}, fmt.Errorf("no passkey code: %w", err)
			}
			reportPasteError(c, err, "type the code again")
			fmt.Fprint(c.stderr, "basalt: Type or paste the code the page shows: ")
			continue
		case strings.HasPrefix(line, passkey.RegistrationResponsePrefix):
			return verifyRegistrationCode(line, req, rp)
		default:
			if cred, ok := matchPairingCode(c, hb, line); ok {
				return cred, nil
			}
		}
		if tries++; tries >= maxPairingTries {
			return passkey.Credential{}, fmt.Errorf("%d codes did not match the passkey the page sent; nothing was stored: run basalt init again", maxPairingTries)
		}
		fmt.Fprint(c.stderr, "basalt: Type or paste the code the page shows: ")
	}
}

// maxPairingTries is how many codes init reads before it gives up: with a
// 40-bit code and at most maxHandBacks registrations kept, guessing fails.
const maxPairingTries = 3

// maxPasteErrors is how many unreadable pastes init takes before it gives
// up; they are not wrong codes.
const maxPasteErrors = 10

// readPairingLine reads one non-empty line the person types or pastes. It
// waits in the background so the command's context still ends the wait.
// When *full closes (the hand-back holds as many passkeys as it takes, so
// the person's may have been refused) it says, once, to paste the long code
// if the page shows no pairing code.
func readPairingLine(c *cliIO, full *chan struct{}) (string, error) {
	pastes, stop := c.pasteInBackground(c.ctx)
	defer stop()
	for {
		select {
		case p := <-pastes:
			return p.code, p.err
		case <-*full:
			*full = nil
			fmt.Fprintln(c.stderr, "\nbasalt: basalt init received more passkeys than expected; if the page shows no pairing code, paste the long code from it")
		case <-c.ctx.Done():
			return "", c.ctx.Err()
		}
	}
}

// matchPairingCode is the kept registration whose pairing code is line, or
// false with the reason said on stderr.
func matchPairingCode(c *cliIO, hb *registrationHandBack, line string) (passkey.Credential, bool) {
	code, ok := passkey.NormalizePairingCode(line)
	if !ok {
		fmt.Fprintln(c.stderr, "basalt: that is not the code the page shows (8 letters and digits, like K7Q2-9MX4); check the page")
		return passkey.Credential{}, false
	}
	switch cred, n := hb.match(code); n {
	case 1:
		fmt.Fprintln(c.stderr, "basalt: the code matches the passkey the page sent to basalt init")
		return cred, true
	case 0:
		fmt.Fprintln(c.stderr, "basalt: that code doesn't match; check the page")
	default: // two posted keys with one code: refuse rather than pick
		fmt.Fprintln(c.stderr, "basalt: that code matches more than one passkey sent to basalt init, so it cannot tell which is yours; check the page")
	}
	return passkey.Credential{}, false
}

// verifyRegistrationCode checks a pasted registration code against req
// (setuprun.VerifyRegistrationCode).
func verifyRegistrationCode(code string, req passkey.RegistrationRequest, rp passkey.Relying) (passkey.Credential, error) {
	return setuprun.VerifyRegistrationCode(code, req, rp)
}

// passkeyStep registers the person's passkey unless an active one is
// registered already for the target origin (--add-passkey registers
// another) or --skip-passkey.
func passkeyStep(c *cliIO, conn *pgx.Conn, f initFlags) error {
	if f.skipPasskey {
		fmt.Fprintln(c.stderr, "basalt: no passkey registered (--skip-passkey); held writes cannot be approved until you run basalt init again without it")
		return nil
	}
	rp, err := relyingParty(f.passkeyOrigin)
	if err != nil {
		return err
	}
	has, err := hasPasskeyFor(c, conn, rp.Origin)
	if err != nil {
		return err
	}
	if has && !f.addPasskey {
		return nil
	}
	label := f.passkeyLabel
	if label == "" {
		label = defaultPasskeyLabel(conn.Config().Database, f.agent, c.now())
	}
	if err := registerPasskey(c, conn, rp, label); err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: passkey registered for %s\n", rp.RPID)
	return nil
}

// serveLocalPages serves the embedded pages on a local http://localhost
// origin while basalt init waits for the registration code, so the link
// works without a separate page server (the engine serves them later,
// CONTRACT.md, Local pages). It serves nothing for another origin, or when
// the port is taken (a page server already runs there). stop ends it and
// frees the port. With hb it also serves the registration hand-back route
// (CONTRACT.md, CLI).
func serveLocalPages(origin string, hb *registrationHandBack) (stop func(), served bool) {
	noop := func() {}
	addr, ok := localPagesAddr(origin)
	if !ok {
		return noop, false
	}
	// No agents: the registration page only, no short links.
	site := pages.New(origin, slog.New(slog.DiscardHandler))
	routes := site.Handler()
	if hb != nil {
		mux := http.NewServeMux()
		mux.Handle("POST "+handBackPath, hb)
		mux.Handle("/", routes)
		routes = mux
	}
	ln, h, err := server.Listen(server.Options{}, "registration page", addr, routes)
	if err != nil {
		return noop, false
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: pageHeaderTimeout, ReadTimeout: pageReadTimeout}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = hs.Serve(ln)
	}()
	// stop releases the port before it returns: the engine service init
	// installs next listens there, and fails while init still holds it.
	return func() {
		_ = hs.Close()
		_ = ln.Close()
		<-done
	}, true
}

// pageHeaderTimeout bounds a page request's headers.
const pageHeaderTimeout = 10 * time.Second

// pageReadTimeout bounds a whole page request, body included, so a post to
// the hand-back route that stalls its body is dropped.
const pageReadTimeout = pageHeaderTimeout + handBackReadTimeout

// localPagesAddr is the loopback address for a local development origin
// http://localhost:<port>, the default the engine's config resolves to.
func localPagesAddr(origin string) (string, bool) {
	p, err := config.Config{PagesURL: origin}.Pages()
	if err != nil || p.Addr == "" {
		return "", false
	}
	return p.Addr, true
}
