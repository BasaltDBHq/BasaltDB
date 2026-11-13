package main

import (
	"errors"
	"fmt"
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
)

// maxPasskeyLabel is the registration request's label limit in bytes.
const maxPasskeyLabel = 64

// relyingParty is the hosted console, or the portal an agent-operated engine
// uses (both RP ID basaltvault.app), for their origins, else the engine's local pages at origin (http://localhost:<port>,
// RP ID localhost), the default until hosting exists.
func relyingParty(origin string) (passkey.Relying, error) {
	if origin == links.HostedConsole {
		return passkey.Production, nil
	}
	if origin == links.Portal {
		return portalRP, nil
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

// hasPasskey reports whether a passkey is registered for this database.
func hasPasskey(c *cliIO, conn *pgx.Conn) (bool, error) {
	var ok bool
	// Plain SQL: a presence check on the admin connection.
	err := conn.QueryRow(c.ctx, `SELECT EXISTS (SELECT 1 FROM basalt_meta.passkeys)`).Scan(&ok)
	return ok, err
}

// registerPasskey is basalt init's passkey step: print the registration
// link, read the code the page shows, verify it, and store the public key
// with the admin connection (owner decision #3; CONTRACT.md, Approvals).
// With open it also opens the link in the browser (basalt init
// --setup-code at a terminal).
func registerPasskey(c *cliIO, conn *pgx.Conn, rp passkey.Relying, label string, open bool) error {
	db := conn.Config().Database
	display := "BasaltDB · " + db
	if len(display) > maxPasskeyLabel {
		display = label
	}
	req, err := passkey.NewRegistrationRequest(c.rand, label, display)
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
	fmt.Fprintln(c.stderr, "basalt: register the passkey that approves this agent's held writes. Open this link on your phone or computer:")
	ref := linkRef{setting: "--passkey-origin", item: "the passkey registration", again: "basalt init"}
	link := links.Register(rp.Origin) + "#" + frag
	if err := printLink(c, c.stderr, link, ref); err != nil {
		return err
	}
	if open {
		if err := c.host.OpenURL(c.ctx, link); err != nil {
			fmt.Fprintf(c.stderr, "basalt: could not open a browser (%v); open the link above yourself\n", err)
		}
	}
	if rp != passkey.Production && !served {
		fmt.Fprint(c.stderr, serveHint(rp.Origin))
	}
	cred, err := readRegistration(c, req, rp, hb)
	if err != nil {
		return err
	}
	return guard.RegisterPasskey(c.ctx, conn, cred, label)
}

// readRegistration waits for the passkey of req: from the page through hb
// when init serves the page, or as a pasted code, which is also taken while
// waiting for the page. A closed stdin leaves the page to send it.
func readRegistration(c *cliIO, req passkey.RegistrationRequest, rp passkey.Relying, hb *registrationHandBack) (passkey.Credential, error) {
	if hb == nil {
		fmt.Fprint(c.stderr, "Paste the code the page shows: ")
		code, err := c.pasted(c.ctx)
		if err != nil {
			return passkey.Credential{}, fmt.Errorf("no passkey code: %w", err)
		}
		return verifyRegistrationCode(code, req, rp)
	}
	fmt.Fprint(c.stderr, "basalt: waiting for the page to send the passkey to basalt init (or paste the code it shows here): ")
	pastes, stopPaste := c.pasteInBackground(c.ctx)
	defer stopPaste()
	for {
		select {
		case cred := <-hb.received:
			stopPaste()
			fmt.Fprintln(c.stderr)
			fmt.Fprintln(c.stderr, "basalt: the page sent the passkey to basalt init")
			return cred, nil
		case p := <-pastes:
			if p.err == nil {
				return verifyRegistrationCode(p.code, req, rp)
			}
			if c.ctx.Err() != nil {
				return passkey.Credential{}, fmt.Errorf("no passkey code: %w", c.ctx.Err())
			}
			reportPasteError(c, p.err, "waiting for the page")
			pastes = nil // only the page can answer now
		case <-c.ctx.Done():
			stopPaste()
			return passkey.Credential{}, fmt.Errorf("no passkey code: %w", c.ctx.Err())
		}
	}
}

// verifyRegistrationCode checks a pasted registration code against req.
func verifyRegistrationCode(code string, req passkey.RegistrationRequest, rp passkey.Relying) (passkey.Credential, error) {
	if strings.TrimSpace(code) == "" {
		return passkey.Credential{}, errors.New("no passkey code given")
	}
	resp, err := passkey.ParseRegistrationResponse(code)
	if err != nil {
		return passkey.Credential{}, err
	}
	return passkey.VerifyRegistration(req, resp, rp)
}

// passkeyStep registers the person's passkey unless one is registered
// already (--add-passkey registers another) or --skip-passkey.
func passkeyStep(c *cliIO, conn *pgx.Conn, f initFlags) error {
	if f.skipPasskey {
		fmt.Fprintln(c.stderr, "basalt: no passkey registered (--skip-passkey); held writes cannot be approved until you run basalt init again without it")
		return nil
	}
	has, err := hasPasskey(c, conn)
	if err != nil {
		return err
	}
	if has && !f.addPasskey {
		return nil
	}
	rp, err := relyingParty(f.passkeyOrigin)
	if err != nil {
		return err
	}
	label := f.passkeyLabel
	if label == "" {
		label = defaultPasskeyLabel(conn.Config().Database, f.agent, c.now())
	}
	if err := registerPasskey(c, conn, rp, label, false); err != nil {
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
	hs := &http.Server{Handler: h, ReadHeaderTimeout: pageHeaderTimeout}
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

// localPagesAddr is the loopback address for a local development origin
// http://localhost:<port>, the default the engine's config resolves to.
func localPagesAddr(origin string) (string, bool) {
	p, err := config.Config{PagesURL: origin}.Pages()
	if err != nil || p.Addr == "" {
		return "", false
	}
	return p.Addr, true
}
