package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/links"
)

// PagesOff disables the engine's local pages listener.
const PagesOff = "off"

// loopbackV4 is the address the local pages bind by default.
const loopbackV4 = "127.0.0.1"

// Pages is where the engine serves the approval and revert pages
// (CONTRACT.md, Local pages): the loopback address it binds and the origin
// the links use. Addr is "" when the engine serves no pages (the hosted
// console, or pagesAddr off).
type Pages struct {
	Addr   string
	Origin string
}

// PagesBase is the base URL every approval, revert and registration link
// uses (links): pagesUrl; else the origin of the older approvalPage key;
// else the engine's local pages, the default until hosting exists (owner
// decisions, Decided Nov 12).
func (c Config) PagesBase() (string, error) {
	switch {
	case c.PagesURL != "":
		return checkBase("pagesUrl", c.PagesURL)
	case c.ApprovalPage != "":
		if err := links.CheckURL(c.ApprovalPage); err != nil {
			return "", fmt.Errorf("approvalPage: %w; set it to an https:// URL, or http://localhost:<port>, of printable characters", err)
		}
		u, err := url.Parse(c.ApprovalPage)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", errors.New("approvalPage is not a URL")
		}
		return checkBase("pagesUrl", u.Scheme+"://"+u.Host)
	}
	return links.DefaultLocal, nil
}

// checkBase accepts the closed list of page origins (CONTRACT.md, Page
// origins; CO-8): the portal, or a local http origin
// (http://localhost:<port>, or a loopback IP), no path. Whether a local
// origin is allowed for this engine's operator is checkOrigins'.
// CheckPagesURL is the check config load runs on pagesUrl, for the
// --pages-url flag to run too; setting names it in the message.
func CheckPagesURL(setting, base string) error {
	_, err := checkBase(setting, base)
	return err
}

func checkBase(setting, base string) (string, error) {
	if err := links.CheckBase(strings.TrimSuffix(base, "/")); err != nil {
		return "", fmt.Errorf("%s: %w; set it to an https:// URL, or http://localhost:<port>, of printable characters", setting, err)
	}
	base = strings.TrimSuffix(base, "/")
	if isHosted(base) {
		return base, nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || !isLoopbackName(u.Hostname()) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%s %q: use %s or a local http://localhost:<port>", setting, base, links.Portal)
	}
	if u.Hostname() != localPagesHost {
		// A passkey's origin, and so every page a link opens, is
		// http://localhost:<port> (RP ID localhost): a page opened on a
		// loopback IP, or another spelling, refuses to run. Refused, not
		// rewritten, so the config says what the engine uses.
		port := u.Port()
		if port == "" {
			port = "<port>"
		}
		return "", fmt.Errorf("%s %q: the local pages run only at localhost; use http://localhost:%s", setting, base, port)
	}
	return base, nil
}

// localPagesHost is the only host of a local pages base.
const localPagesHost = "localhost"

// Pages resolves pagesAddr against the pages' base URL. Default: on, at
// 127.0.0.1 and the base's port, when the base is local; off for the
// portal. A non-loopback or hostname address is refused: names are
// never trusted for listen policy, and this listener has no TLS.
func (c Config) Pages() (Pages, error) {
	base, err := c.PagesBase()
	if err != nil {
		return Pages{}, err
	}
	if c.PagesAddr == PagesOff {
		return Pages{}, nil
	}
	if isHosted(base) {
		if c.PagesAddr != "" {
			return Pages{}, errors.New("pagesAddr needs a local pagesUrl (http://localhost:<port>): the pages must be on the passkey's origin")
		}
		return Pages{}, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return Pages{}, err
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	addr := c.PagesAddr
	if addr == "" {
		addr = net.JoinHostPort(loopbackV4, port)
	}
	if err := checkLoopbackAddr(addr); err != nil {
		return Pages{}, err
	}
	return Pages{Addr: addr, Origin: base}, nil
}

// isHosted reports whether base is the portal, which the engine does not
// serve.
func isHosted(base string) bool {
	return base == links.Portal
}

// DevLocalPagesWarning is the line every personMessage starts with, and
// what init and the engine's log say, while devLocalPages is on
// (CONTRACT.md, Page origins).
const DevLocalPagesWarning = "DEV_LOCAL_PAGES: these pages are on the agent's machine; never use this with a bot you do not control"

// checkOrigins applies the operator half of the closed origin list (CO-8):
// an agent-operated engine uses the portal, since local pages would be on
// the agent's machine, unless devLocalPages is on; devLocalPages holds
// only for an agent-operated engine serving local pages on loopback.
func (c Config) checkOrigins() error {
	base, err := c.PagesBase()
	if err != nil {
		return err
	}
	local := !isHosted(base)
	switch {
	case c.DevLocalPages && !c.AgentOperated():
		return errors.New(`devLocalPages is only for an agent-operated engine ("operatedBy": "AGENT"); remove it`)
	case c.DevLocalPages && !local:
		return fmt.Errorf("devLocalPages needs a local pagesUrl (http://localhost:<port>), not %s; remove it", base)
	case c.DevLocalPages && c.PagesAddr == PagesOff:
		return fmt.Errorf("devLocalPages needs the engine to serve the pages on loopback; remove \"pagesAddr\": %q or devLocalPages", PagesOff)
	case c.AgentOperated() && local && !c.DevLocalPages:
		return fmt.Errorf("pagesUrl %s: an agent-operated engine uses the portal's pages (%s); local pages would be on the agent's machine",
			base, links.Portal)
	}
	return nil
}

// isLoopbackName reports whether host names this machine in a URL; a
// local pages base must then be localhost itself (checkBase).
func isLoopbackName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkLoopbackAddr refuses a pages address that is not a literal loopback
// IP and port.
func checkLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("pagesAddr %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("pagesAddr %q: the pages listen on a loopback IP only (127.0.0.1 or ::1), or set it to %q", addr, PagesOff)
	}
	return nil
}
