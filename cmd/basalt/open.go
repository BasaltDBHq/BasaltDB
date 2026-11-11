package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// linkPages is where a command's links point: the base URL of the long
// link's pages (links), and the origin of the engine's local pages when it
// serves them ("" when not).
type linkPages struct {
	base  string
	local string
}

// short is the short link page(local, id) when the engine serves the
// pages, else long.
func (p linkPages) short(page func(string, uuid.UUID) string, id uuid.UUID, long string) string {
	if p.local == "" {
		return long
	}
	return page(p.local, id)
}

// nextStep says what follows the signature: the page relays it when the
// engine served it, else the person pastes the code into paste.
func (p linkPages) nextStep(sign, paste string) string {
	if p.local != "" {
		return sign + "; the page sends it to the engine, nothing to paste."
	}
	return sign + ", then run " + paste + " with the code the page shows."
}

// localPages is the origin of the pages the engine serves for the agent's
// config when it answers there, or "": an explicit --pages-url, no
// --agent, pages off, or no engine running.
func localPages(c *cliIO, pagesURL, agent, configPath string) string {
	if pagesURL != "" || agent == "" {
		return ""
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return ""
	}
	p, err := cfg.Pages()
	if err != nil || p.Addr == "" || !c.host.PagesUp(c.ctx, p.Origin) {
		return ""
	}
	return p.Origin
}

// openLink opens an approval or revert link in the default browser. The
// links carry the whole preview and run to thousands of characters, which
// terminals wrap and chats cut, so opening them from here is the reliable
// path. When no browser opens, the link goes to fallback to copy by hand.
func openLink(c *cliIO, link string, fallback io.Writer) {
	err := checkWebLink(link)
	if err == nil {
		err = c.host.OpenURL(c.ctx, link)
	}
	if err != nil {
		fmt.Fprintf(c.stderr, "basalt: could not open a browser (%v); open this link yourself:\n", err)
		fmt.Fprintln(fallback, link)
		return
	}
	fmt.Fprintln(c.stderr, "basalt: opened the link in your browser")
}

// checkWebLink refuses anything but an http or https URL, so a --page value
// is never handed to the opener as an option or a local file.
func checkWebLink(link string) error {
	u, err := url.Parse(link)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("the page is not an http or https URL")
	}
	return nil
}

// configuredBase is the base URL a link points to: --pages-url when
// given, else the engine config's (PagesBase) when the agent comes from
// that config, else the engine's local pages, the default until hosting.
func configuredBase(pagesURL, agent, configPath string) string {
	if pagesURL != "" {
		return pagesURL
	}
	if agent == "" {
		return links.DefaultLocal
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return links.DefaultLocal // agentURL already reported a config it could not load
	}
	base, err := cfg.PagesBase()
	if err != nil {
		return links.DefaultLocal
	}
	return base
}
