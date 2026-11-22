package shim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"time"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// openTimeout bounds one run of the browser opener: xdg-open may hang
// without a desktop, and nothing waits on it.
const openTimeout = 10 * time.Second

// linksKey is in every answer that carries a links list; most answers
// have none and are not decoded.
var linksKey = []byte(`links`)

// autoOpener opens in the browser the links of the engine's answers that
// point to the engine's own local pages, on a person-operated engine only
// (CONTRACT.md, Auto-open). The answer reaches the client unchanged, link
// included, and never waits on the opener. Each link opens once per
// process, so a result that repeats it does not open another tab.
type autoOpener struct {
	open func(ctx context.Context, link string) error

	mu   sync.Mutex
	seen map[string]bool
}

// newAutoOpener is the opener that runs open; nil when open is nil.
func newAutoOpener(open func(ctx context.Context, link string) error) *autoOpener {
	if open == nil {
		return nil
	}
	return &autoOpener{open: open, seen: map[string]bool{}}
}

// answer opens the links of line, an engine's answer on a connection whose
// hello answer was engine. It opens nothing unless the engine said it is
// operated by a person and gave its local page origin.
func (o *autoOpener) answer(ctx context.Context, engine mcp.Hello, line []byte) {
	if o == nil || engine.OperatedBy != mcpcontract.OperatedByPerson {
		return
	}
	origin, ok := pageOrigin(engine.PagesOrigin)
	if !ok {
		return
	}
	for _, link := range resultLinks(line) {
		if !onOrigin(link, origin) || !o.first(link) {
			continue
		}
		go o.run(ctx, link)
	}
}

// first reports whether link was not opened before, and marks it opened.
func (o *autoOpener) first(link string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen[link] {
		return false
	}
	o.seen[link] = true
	return true
}

func (o *autoOpener) run(ctx context.Context, link string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), openTimeout)
	defer cancel()
	// The agent shows the link too: a browser that did not open is the
	// person's to open by hand, so the error is not reported.
	_ = o.open(ctx, link)
}

// pageOrigin is the scheme and host (with port) of the engine's local
// page origin; false when it is not a loopback http URL with nothing but
// an origin.
func pageOrigin(origin string) (*url.URL, bool) {
	if origin == "" || links.CheckURL(origin) != nil {
		return nil, false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, false
	}
	return u, true
}

// onOrigin reports whether link is a URL under the URL rule whose scheme,
// host and port are origin's.
func onOrigin(link string, origin *url.URL) bool {
	if links.CheckURL(link) != nil {
		return false
	}
	u, err := url.Parse(link)
	if err != nil || u.User != nil {
		return false
	}
	return u.Scheme == origin.Scheme && u.Host == origin.Host
}

// resultLinks are the URLs of the links lists of a tools/call answer that
// hands over a link: the body's own and its held approval's (a held write,
// request_revert, a plugin approval, a passkey or setup page). Nothing else
// is read: list items and status problems restate links a person already
// has, and free text and query rows carry database content.
func resultLinks(line []byte) []string {
	if !bytes.Contains(line, linksKey) {
		return nil
	}
	var msg struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(line, &msg) != nil {
		return nil
	}
	var out []string
	for _, c := range msg.Result.Content {
		if c.Type != "text" {
			continue
		}
		var body linkedBody
		if json.Unmarshal([]byte(c.Text), &body) != nil {
			continue
		}
		out = body.urls(out)
	}
	return out
}

// linkedBody is the part of a result body that may carry links lists.
type linkedBody struct {
	Links    []mcp.Link `json:"links"`
	Approval *struct {
		Links []mcp.Link `json:"links"`
	} `json:"approval"`
}

func (b linkedBody) urls(out []string) []string {
	out = linkURLs(out, b.Links)
	if b.Approval != nil {
		out = linkURLs(out, b.Approval.Links)
	}
	return out
}

func linkURLs(out []string, ls []mcp.Link) []string {
	for _, l := range ls {
		out = append(out, l.URL)
	}
	return out
}
