package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/basaltdbhq/basaltdb/internal/links"
)

// localPages is the origin of the pages the engine serves for the agent's
// config when it answers there, or "": an explicit --pages-url, no
// --agent, pages off, or no engine running.
func localPages(c *cliIO, pagesURL, agent, configPath string) string {
	if pagesURL != "" || agent == "" {
		return ""
	}
	cfg, err := loadEngineConfig(c, configPath)
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
// A link that breaks the URL rule is neither opened nor printed.
func openLink(c *cliIO, link string, fallback io.Writer, ref linkRef) error {
	if err := links.CheckURL(link); err != nil {
		return refusedLink(err, ref)
	}
	err := checkWebLink(link)
	if err == nil {
		err = c.host.OpenURL(c.ctx, link)
	}
	if err != nil {
		fmt.Fprintf(c.stderr, "basalt: could not open a browser (%v); open this link yourself:\n", err)
		return printLink(c, fallback, link, ref)
	}
	fmt.Fprintln(c.stderr, "basalt: opened the link in your browser")
	return nil
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
func configuredBase(c *cliIO, pagesURL, agent, configPath string) string {
	if pagesURL != "" {
		return pagesURL
	}
	if agent == "" {
		return links.DefaultLocal
	}
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return links.DefaultLocal // agentURL already reported a config it could not load
	}
	base, err := cfg.PagesBase()
	if err != nil {
		return links.DefaultLocal
	}
	return base
}
