package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/server"
	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// maxPasskeyLabel is the registration request's label limit in bytes.
const maxPasskeyLabel = setuprun.MaxPasskeyLabel

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
