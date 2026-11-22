package main

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/setuprun"
)

// maxPasskeyLabel is the registration request's label limit in bytes.
const maxPasskeyLabel = setuprun.MaxPasskeyLabel

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
