package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
	stop, served := serveLocalPages(rp.Origin)
	defer stop()
	if rp != passkey.Production && !served {
		fmt.Fprint(c.stderr, serveHint(rp.Origin))
	}
	fmt.Fprint(c.stderr, "Paste the code the page shows: ")
	code, err := c.line()
	if err != nil {
		return fmt.Errorf("no passkey code: %w", err)
	}
	if strings.TrimSpace(code) == "" {
		return errors.New("no passkey code given")
	}
	resp, err := passkey.ParseRegistrationResponse(code)
	if err != nil {
		return err
	}
	cred, err := passkey.VerifyRegistration(req, resp, rp)
	if err != nil {
		return err
	}
	return guard.RegisterPasskey(c.ctx, conn, cred, label)
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
		label = conn.Config().Database
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
// the port is taken (a page server already runs there). stop ends it.
func serveLocalPages(origin string) (stop func(), served bool) {
	noop := func() {}
	addr, ok := localPagesAddr(origin)
	if !ok {
		return noop, false
	}
	// No agents: the registration page only, no short links.
	site := pages.New(origin, slog.New(slog.DiscardHandler))
	ln, h, err := server.Listen(server.Options{}, "registration page", addr, site.Handler())
	if err != nil {
		return noop, false
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: pageHeaderTimeout}
	go func() { _ = hs.Serve(ln) }()
	return func() { _ = hs.Close() }, true
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
