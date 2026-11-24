package status

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"

	"github.com/basaltdbhq/basaltdb/internal/lib/httpsec"
	"github.com/basaltdbhq/basaltdb/web"
)

// Interval is the time between two checks.
const Interval = 24 * time.Hour

// fileName is the result's file in the engine's state directory.
const fileName = "portal-check.json"

// maxFindings bounds the paths a result keeps.
const maxFindings = 100

// Result is the outcome of one check.
type Result struct {
	// PortalURL is the portal that was checked.
	PortalURL string `json:"portalUrl"`
	// CheckedAt is when the check finished.
	CheckedAt time.Time `json:"checkedAt"`
	// Error says why the portal could not be checked at all.
	Error string `json:"error,omitempty"`
	// Findings are the paths with DIFFERS, MISSING, HEADER or UNEXPECTED, at
	// most maxFindings in path order.
	Findings []File `json:"findings,omitempty"`
	// Total is how many paths had one of those statuses.
	Total int `json:"total,omitempty"`
	// Unchecked is how many paths could not be checked (status ERROR).
	Unchecked int `json:"unchecked,omitempty"`
}

// Mismatch reports whether the portal serves something other than the pages
// this binary embeds. A check that could not run is not a mismatch.
func (r Result) Mismatch() bool { return r.Total > 0 }

// Summary counts the mismatching paths by status, in a fixed order, for
// example "2 DIFFERS, 1 MISSING". Empty when nothing mismatches.
func (r Result) Summary() string {
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Status]++
	}
	var parts []string
	for _, s := range []string{StatusDiffers, StatusMissing, StatusHeader, StatusUnexpected} {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	out := strings.Join(parts, ", ")
	if r.Total > len(r.Findings) {
		out += fmt.Sprintf(" (and %d more)", r.Total-len(r.Findings))
	}
	return out
}

// mismatching are the statuses that make a result a mismatch.
func mismatching(status string) bool {
	switch status {
	case StatusDiffers, StatusMissing, StatusHeader, StatusUnexpected:
		return true
	}
	return false
}

// resultOf reduces a verify report to a Result.
func resultOf(rep *Report, now time.Time) Result {
	r := Result{PortalURL: rep.PortalURL, CheckedAt: now}
	for _, f := range rep.Files {
		switch {
		case mismatching(f.Status):
			r.Total++
			if len(r.Findings) < maxFindings {
				r.Findings = append(r.Findings, f)
			}
		case f.Status == StatusError:
			r.Unchecked++
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Path < r.Findings[j].Path })
	return r
}

// connectPageFile is the connect page's embedded file.
const connectPageFile = "connect/index.html"

// PortalcheckOptions is what the check compares and how it is run for base, the
// portal's origin: the pages embedded in this binary, the routes people load
// pages at and the headers they must carry. basalt portal verify uses the
// same.
func PortalcheckOptions(base string) PortalverifyOptions {
	o := PortalverifyOptions{
		Base: base, Files: web.Files, Headers: httpsec.ExpectedPortal(),
		// The connect page reaches the connect service (CONTRACT.md, The
		// connect page): its own policy, never stored.
		FileHeaders: map[string]http.Header{connectPageFile: httpsec.ExpectedConnectPage()},
	}
	for _, r := range web.PortalPages() {
		o.Routes = append(o.Routes, Route{Path: r.Path, ID: r.ID, File: r.File})
	}
	return o
}

// Checker runs the daily check and remembers its last result.
type Checker struct {
	opts     PortalverifyOptions
	stateDir string
	log      *slog.Logger
	now      func() time.Time
	// verify is Verify; tests replace it.
	verify func(context.Context, PortalverifyOptions) (*Report, error)

	mu   sync.Mutex
	last *Result
}

// New returns a checker for the portal at opts.Base. Results are also
// written to stateDir (fileName) unless it is empty.
func New(opts PortalverifyOptions, stateDir string, log *slog.Logger, now func() time.Time) *Checker {
	return &Checker{opts: opts, stateDir: stateDir, log: log, now: now, verify: Verify}
}

// Last is the result of the most recent check, false before the first.
func (c *Checker) Last() (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return Result{}, false
	}
	return *c.last, true
}

// Check runs one check now and keeps its result.
func (c *Checker) Check(ctx context.Context) Result {
	rep, err := c.verify(ctx, c.opts)
	var res Result
	if err != nil {
		res = Result{PortalURL: c.opts.Base, CheckedAt: c.now(), Error: err.Error()}
	} else {
		res = resultOf(rep, c.now())
	}
	c.mu.Lock()
	c.last = &res
	c.mu.Unlock()
	switch {
	case res.Mismatch():
		c.log.Warn("the portal serves pages that differ from this build",
			"portal", res.PortalURL, "paths", res.Summary())
	case res.Error != "":
		c.log.Warn("the portal could not be checked", "portal", res.PortalURL, "err", res.Error)
	case res.Unchecked > 0:
		c.log.Info("some portal paths could not be checked", "portal", res.PortalURL, "paths", res.Unchecked)
	default:
		c.log.Info("the portal serves the pages of this build", "portal", res.PortalURL)
	}
	if c.stateDir != "" {
		if err := save(c.stateDir, res); err != nil {
			c.log.Warn("the portal check result was not saved", "err", err)
		}
	}
	return res
}

// Run checks once at once and then every interval, until ctx ends.
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	c.Check(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Check(ctx)
		}
	}
}

// save writes res to dir/fileName (0600), replacing the old one.
func save(dir string, res Result) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, fileName), b, atomicfile.Options{Mode: resultFileMode})
}

// resultFileMode keeps the check result to its own user.
const resultFileMode = 0o600
