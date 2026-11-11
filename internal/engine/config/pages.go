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
		return checkBase(c.PagesURL)
	case c.ApprovalPage != "":
		u, err := url.Parse(c.ApprovalPage)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", fmt.Errorf("approvalPage %q is not a URL", c.ApprovalPage)
		}
		return checkBase(u.Scheme + "://" + u.Host)
	}
	return links.DefaultLocal, nil
}

// checkBase accepts the hosted console or a local http origin
// (http://localhost:<port>, or a loopback IP): an origin, no path.
func checkBase(base string) (string, error) {
	base = strings.TrimSuffix(base, "/")
	if base == links.HostedConsole {
		return base, nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "http" || !isLoopbackName(u.Hostname()) || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("pagesUrl %q: use %s or a local http://localhost:<port>", base, links.HostedConsole)
	}
	return base, nil
}

// Pages resolves pagesAddr against the pages' base URL. Default: on, at
// 127.0.0.1 and the base's port, when the base is local; off for the
// hosted console. A non-loopback or hostname address is refused: names are
// never trusted for listen policy, and this listener has no TLS.
func (c Config) Pages() (Pages, error) {
	base, err := c.PagesBase()
	if err != nil {
		return Pages{}, err
	}
	if c.PagesAddr == PagesOff {
		return Pages{}, nil
	}
	if base == links.HostedConsole {
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

// isLoopbackName reports whether host names this machine in a URL.
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
