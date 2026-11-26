// Package portalfetch fetches the portal's paths for the portal check
// (the status domain's PageFetcher): a GET with no-cache that follows
// redirects only within the portal's origin.
package portalfetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"
)

const (
	requestTimeout = 20 * time.Second
	maxRedirects   = 5
)

// Fetcher fetches paths under one portal origin.
type Fetcher struct {
	base   string
	client *http.Client
}

// New is a fetcher for the portal at base, its origin without a trailing
// slash.
func New(base string) *Fetcher { return &Fetcher{base: base, client: newClient(base)} }

// Get fetches urlPath under the portal's origin: the status code, the
// response header and at most limit bytes of the body. Its error is the
// reason the report shows (errText).
func (f *Fetcher) Get(ctx context.Context, urlPath string, limit int64) (int, textproto.MIMEHeader, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+urlPath, http.NoBody)
	if err != nil {
		return 0, nil, nil, reason(err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := f.client.Do(req)
	if err != nil {
		return 0, nil, nil, reason(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, textproto.MIMEHeader(resp.Header), body, reason(err)
}

// reason is err reduced to the text the report shows, or nil.
func reason(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(errText(err))
}

var errOffOrigin = errors.New("redirected to another origin; not followed")

// newClient returns a client that follows redirects only within base's
// origin.
func newClient(base string) *http.Client {
	u, _ := url.Parse(base)
	return &http.Client{
		Timeout: requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if u == nil || !sameOrigin(req.URL, u) {
				return errOffOrigin
			}
			if len(via) >= maxRedirects {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// sameOrigin compares scheme, lower-cased host and port, the default port
// being implied.
func sameOrigin(a, b *url.URL) bool {
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// errText is the reason a path could not be fetched, as the report shows
// it: the off-origin redirect, or the transport's own error without the
// URL around it.
func errText(err error) string {
	if errors.Is(err, errOffOrigin) {
		return errOffOrigin.Error()
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
