package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// revertSibling is the revert page relative to the approval page: both are
// served from the same origin (web/approve, web/revert).
const revertSibling = "../revert/"

// revertPagePath is the revert page on the engine's local pages, as
// approvePath is the approval page (CONTRACT.md, Local pages).
const revertPagePath = "/revert/"

// linkPages is where a command's links point: the page of the long link,
// and the origin of the engine's local pages when it serves them ("" when
// not).
type linkPages struct {
	page  string
	local string
}

// short is the short link <local><path><id> when the engine serves the
// pages, else long.
func (p linkPages) short(path string, id uuid.UUID, long string) string {
	if p.local == "" {
		return long
	}
	return p.local + path + id.String()
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
// config when it answers there, or "": an explicit --page, no --agent,
// pages off, or no engine running.
func localPages(c *cliIO, page, agent, configPath string) string {
	if page != "" || agent == "" {
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

// configuredPage is the page a link points to: --page when given, else
// the engine config's approvalPage (resolved against sibling, "" for the
// approval page itself) when the agent comes from that config, else def.
// A development setup keeps its local page in the config, so the person
// does not repeat --page.
func configuredPage(page, def, agent, configPath, sibling string) string {
	if page != "" {
		return page
	}
	if agent == "" {
		return def
	}
	cfg, err := config.Load(configPath)
	if err != nil || cfg.ApprovalPage == "" {
		return def // agentURL already reported a config it could not load
	}
	base, err := url.Parse(cfg.ApprovalPage)
	if err != nil {
		return def
	}
	return base.ResolveReference(&url.URL{Path: sibling}).String()
}
