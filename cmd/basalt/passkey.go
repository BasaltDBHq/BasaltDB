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

// serveLocalPages serves the embedded pages on a local http://localhost
// origin while a command waits for a code from them, so the link works
// without a separate page server (the engine serves them later,
// CONTRACT.md, Local pages). It serves nothing for another origin, or when
// the port is taken (a page server already runs there). stop ends it and
// frees the port.
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

// pageReadTimeout bounds a whole page request, body included.
const pageReadTimeout = 2 * pageHeaderTimeout

// localPagesAddr is the loopback address for a local development origin
// http://localhost:<port>, the default the engine's config resolves to.
func localPagesAddr(origin string) (string, bool) {
	p, err := config.Config{PagesURL: origin}.Pages()
	if err != nil || p.Addr == "" {
		return "", false
	}
	return p.Addr, true
}
