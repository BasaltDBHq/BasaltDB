// Package portalcheck is the engine's daily check of the hosted portal
// (CONTRACT.md, CLI, `basalt portal verify`; Next steps, PORTAL_MISMATCH).
// Once a day the engine runs the same comparison as `basalt portal verify`
// against the portal in its config and keeps the answer: in memory for the
// status tool, and in a file in the state directory for `basalt status` on
// an engine that runs as the person. The check reads public pages only and
// sends nothing about the engine. It never stops the engine and never blocks
// a tool: a portal that differs is a warning, not a refusal.
package portalcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/lib/httpsec"
	"github.com/basaltdbhq/basaltdb/internal/service/portalverify"
	"github.com/basaltdbhq/basaltdb/web"
)

// Interval is the time between two checks.
const Interval = 24 * time.Hour

// FileName is the result's file in the engine's state directory.
const FileName = "portal-check.json"

// maxFileBytes bounds what is read back from the result file.
const maxFileBytes = 64 << 10

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
	Findings []portalverify.File `json:"findings,omitempty"`
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
	for _, s := range []string{portalverify.StatusDiffers, portalverify.StatusMissing, portalverify.StatusHeader, portalverify.StatusUnexpected} {
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
	case portalverify.StatusDiffers, portalverify.StatusMissing, portalverify.StatusHeader, portalverify.StatusUnexpected:
		return true
	}
	return false
}

// resultOf reduces a verify report to a Result.
func resultOf(rep *portalverify.Report, now time.Time) Result {
	r := Result{PortalURL: rep.PortalURL, CheckedAt: now}
	for _, f := range rep.Files {
		switch {
		case mismatching(f.Status):
			r.Total++
			if len(r.Findings) < maxFindings {
				r.Findings = append(r.Findings, f)
			}
		case f.Status == portalverify.StatusError:
			r.Unchecked++
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool { return r.Findings[i].Path < r.Findings[j].Path })
	return r
}

// ConnectPageFile is the connect page's embedded file.
const ConnectPageFile = "connect/index.html"

// Options is what the check compares and how it is run for base, the
// portal's origin: the pages embedded in this binary, the routes people load
// pages at and the headers they must carry. basalt portal verify uses the
// same.
func Options(base string) portalverify.Options {
	o := portalverify.Options{
		Base: base, Files: web.Files, Headers: httpsec.ExpectedPortal(),
		// The connect page reaches the connect service (CONTRACT.md, The
		// connect page): its own policy, never stored.
		FileHeaders: map[string]http.Header{ConnectPageFile: httpsec.ExpectedConnectPage()},
	}
	for _, r := range web.PortalPages() {
		o.Routes = append(o.Routes, portalverify.Route{Path: r.Path, ID: r.ID, File: r.File})
	}
	return o
}

// Checker runs the daily check and remembers its last result.
type Checker struct {
	opts     portalverify.Options
	stateDir string
	log      *slog.Logger
	now      func() time.Time
	// verify is portalverify.Verify; tests replace it.
	verify func(context.Context, portalverify.Options) (*portalverify.Report, error)

	mu   sync.Mutex
	last *Result
}

// New returns a checker for the portal at opts.Base. Results are also
// written to stateDir (FileName) unless it is empty.
func New(opts portalverify.Options, stateDir string, log *slog.Logger, now func() time.Time) *Checker {
	return &Checker{opts: opts, stateDir: stateDir, log: log, now: now, verify: portalverify.Verify}
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

// save writes res to dir/FileName (0600), replacing the old one.
func save(dir string, res Result) error {
	b, err := json.Marshal(res)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, FileName+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, FileName)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Load reads the result the engine saved in dir. It is false when there is
// none, when it cannot be read, or when it was made for another portal than
// base: a result of a portal the config no longer names says nothing.
func Load(dir, base string) (Result, bool) {
	f, err := os.Open(filepath.Join(dir, FileName))
	if err != nil {
		return Result{}, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil || len(b) > maxFileBytes {
		return Result{}, false
	}
	var res Result
	if err := json.Unmarshal(b, &res); err != nil || res.PortalURL != base {
		return Result{}, false
	}
	return res, true
}
