package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// PagesOff disables the engine's local pages listener.
const PagesOff = "off"

// defaultApprovalPage is the hosted approval page (approval.PageURL), the
// approval page when the config names none.
const defaultApprovalPage = "https://basaltvault.app/approve/"

// loopbackV4 is the address the local pages bind by default.
const loopbackV4 = "127.0.0.1"

// Pages is where the engine serves the approval and revert pages
// (CONTRACT.md, Local pages): the loopback address it binds and the origin
// the short links use, the approval page's origin. Addr is "" when the
// pages are off.
type Pages struct {
	Addr   string
	Origin string
}

// Pages resolves pagesAddr against the approval page. Default: on, at
// 127.0.0.1 and the page's port, when the approval page is a local
// http://localhost:<port> page (a development passkey origin); off
// otherwise. A non-loopback or hostname address is refused: names are
// never trusted for listen policy, and this listener has no TLS.
func (c Config) Pages() (Pages, error) {
	if c.PagesAddr == PagesOff {
		return Pages{}, nil
	}
	page := c.ApprovalPage
	if page == "" {
		page = defaultApprovalPage
	}
	u, err := url.Parse(page)
	if err != nil {
		return Pages{}, fmt.Errorf("approvalPage: %w", err)
	}
	local := u.Scheme == "http" && isLoopbackName(u.Hostname())
	if !local {
		if c.PagesAddr != "" {
			return Pages{}, errors.New("pagesAddr needs a local approvalPage (http://localhost:<port>/approve/): the pages must be on the passkey's origin")
		}
		return Pages{}, nil
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
	return Pages{Addr: addr, Origin: u.Scheme + "://" + u.Host}, nil
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
