// Package updatecheck tells a person or an agent that a newer BasaltDB
// release is out. It asks the public GitHub releases list of
// BasaltDBHq/BasaltDB at most once a day, keeps the answer in a small cache
// file, and never makes a command wait on the network: callers read the
// cache (Cached) and refresh it on the side (Refresh). The request carries
// no data beyond the HTTP request itself (the IP address and a User-Agent
// with this build's version).
package updatecheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
)

// Tunables, named so the rule stays readable.
const (
	// Interval is how often a refresh asks GitHub.
	Interval = 24 * time.Hour
	// retryAfterFailure is how soon a failed refresh is tried again.
	retryAfterFailure = time.Hour
	// RequestTimeout bounds one refresh request.
	RequestTimeout = 2 * time.Second
	// releasesURL lists the public releases, newest first.
	releasesURL = "https://api.github.com/repos/BasaltDBHq/BasaltDB/releases?per_page=30"
	// releasePageBase is the human page of one release tag.
	releasePageBase = "https://github.com/BasaltDBHq/BasaltDB/releases/tag/"
	// maxBodyBytes bounds the response read.
	maxBodyBytes  = 1 << 20
	cacheFile     = "update-check.json"
	cacheDirPerm  = 0o700
	cacheFilePerm = 0o600
	// DevVersion is the version of a build with no release number: it never
	// gets a notice.
	DevVersion = "0.0.0-dev"
	// EnvDisable turns the check off when set to off, 0, false or no.
	EnvDisable = "BASALT_UPDATE_CHECK"
	// securityPrefix starts the release-notes line that marks a security fix.
	securityPrefix = "security:"
)

// Release is one published release as the cache keeps it.
type Release struct {
	Tag        string `json:"tag"`
	Prerelease bool   `json:"prerelease,omitempty"`
	// Security is true when the release notes carry a line starting
	// "Security:".
	Security bool `json:"security,omitempty"`
}

type cache struct {
	CheckedAt   time.Time `json:"checkedAt"`
	AttemptedAt time.Time `json:"attemptedAt"`
	Releases    []Release `json:"releases"`
}

// Notice says a newer release exists.
type Notice struct {
	Current string `json:"current"`
	Latest  string `json:"latest"`
	// Security is true when a release newer than Current is marked as a
	// security fix.
	Security bool   `json:"security"`
	URL      string `json:"url"`
}

// Disabled reports whether the environment turns the check off.
func Disabled(getenv func(string) string) bool {
	switch strings.ToLower(strings.TrimSpace(getenv(EnvDisable))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// Checker reads and refreshes the cache in Dir for a build at Current.
type Checker struct {
	Dir     string
	Current string
	Now     func() time.Time
	Client  *http.Client
	// URL overrides the releases list, for tests.
	URL string
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Checker) path() string { return filepath.Join(c.Dir, cacheFile) }

func (c *Checker) load() cache {
	raw, err := os.ReadFile(c.path())
	if err != nil {
		return cache{}
	}
	var k cache
	if json.Unmarshal(raw, &k) != nil {
		return cache{}
	}
	return k
}

// Cached is the notice the cache supports, or nil: no cache, no newer
// release, or a build with no release number. It never touches the network.
func (c *Checker) Cached() *Notice {
	return notice(c.Current, c.load().Releases)
}

// releaseCandidateRE matches a release candidate tag such as v0.1.0-alpha-rc.2.
var releaseCandidateRE = regexp.MustCompile(`-rc\.[0-9]+$`)

// releaseCandidate reports whether tag names a release candidate: a build to
// test before a release, never offered to anyone.
func releaseCandidate(tag string) bool { return releaseCandidateRE.MatchString(tag) }

// notice picks the newest release above current that the person may see:
// pre-releases (a tag suffix or GitHub's flag) only when current is one, and
// release candidates never.
func notice(current string, releases []Release) *Notice {
	cur, ok := parseVersion(current)
	if !ok || current == DevVersion {
		return nil
	}
	// A candidate build is older than the release it leads up to, but
	// semantic version order puts v0.1.0-alpha-rc.1 above v0.1.0-alpha: judge
	// it by its base, and count the release itself as newer.
	floor, floorEq := cur, false
	if releaseCandidate(current) {
		if base, ok := parseVersion(releaseCandidateRE.ReplaceAllString(current, "")); ok {
			floor, floorEq = base, true
		}
	}
	var best *Release
	var bestV string
	security := false
	for i := range releases {
		r := &releases[i]
		if releaseCandidate(r.Tag) {
			continue
		}
		v, ok := parseVersion(r.Tag)
		if !ok || ((prerelease(v) || r.Prerelease) && !prerelease(cur)) || older(semver.Compare(v, floor), floorEq) {
			continue
		}
		security = security || r.Security
		if best == nil || semver.Compare(v, bestV) > 0 {
			best, bestV = r, v
		}
	}
	if best == nil {
		return nil
	}
	return &Notice{
		Current:  strings.TrimPrefix(current, "v"),
		Latest:   strings.TrimPrefix(best.Tag, "v"),
		Security: security,
		URL:      releasePageBase + best.Tag,
	}
}

// older reports whether a comparison against the floor rules a release out:
// below it, or equal to it when the floor is a build's own number.
func older(c int, floorEq bool) bool { return c < 0 || (c == 0 && !floorEq) }

// Run refreshes the cache now and then whenever it falls due, until ctx is
// done: for a long-running process (the engine). Errors go to onErr.
func (c *Checker) Run(ctx context.Context, onErr func(error)) {
	t := time.NewTicker(retryAfterFailure)
	defer t.Stop()
	for {
		if err := c.Refresh(ctx); err != nil && onErr != nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Due reports whether Refresh would ask GitHub now.
func (c *Checker) Due() bool {
	k := c.load()
	now := c.now()
	return now.Sub(k.CheckedAt) >= Interval && now.Sub(k.AttemptedAt) >= retryAfterFailure
}

// Refresh asks GitHub when the cache is older than a day (and no attempt
// failed within the last hour) and saves the answer. It returns an error
// for the caller to ignore or log; a failure keeps the old releases.
func (c *Checker) Refresh(ctx context.Context) error {
	if !c.Due() {
		return nil
	}
	k := c.load()
	k.AttemptedAt = c.now()
	// Record the attempt first: a command that exits while the request is
	// still running must not leave the next command to start another one.
	if err := c.save(k); err != nil {
		return err
	}
	releases, err := c.fetch(ctx)
	if err != nil {
		return err
	}
	k.Releases, k.CheckedAt = releases, k.AttemptedAt
	return c.save(k)
}

type githubRelease struct {
	Tag        string `json:"tag_name"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

func (c *Checker) fetch(ctx context.Context) ([]Release, error) {
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	url := c.URL
	if url == "" {
		url = releasesURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "basalt/"+strings.TrimPrefix(c.Current, "v"))
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("releases list: %s", resp.Status)
	}
	var list []githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBodyBytes)).Decode(&list); err != nil {
		return nil, fmt.Errorf("releases list: %w", err)
	}
	out := make([]Release, 0, len(list))
	for _, g := range list {
		if g.Draft {
			continue
		}
		out = append(out, Release{Tag: g.Tag, Prerelease: g.Prerelease, Security: markedSecurity(g.Body)})
	}
	return out, nil
}

// markedSecurity is true when a line of the release notes starts with
// "Security:" (any case).
func markedSecurity(body string) bool {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), securityPrefix) {
			return true
		}
	}
	return false
}

func (c *Checker) save(k cache) error {
	if err := os.MkdirAll(c.Dir, cacheDirPerm); err != nil {
		return err
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return err
	}
	return atomicfile.Write(c.path(), raw, atomicfile.Options{Mode: cacheFilePerm})
}

// ErrNoDir is returned by CacheDir when no cache directory can be found.
var ErrNoDir = errors.New("no cache directory")

// CacheDir is the user cache directory's basalt folder.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoDir, err)
	}
	return filepath.Join(base, "basalt"), nil
}

// UpgradeHint is how to get the new release: the brew command when the
// running binary sits in a Homebrew prefix, else the release page.
func (n Notice) UpgradeHint(exePath string) string {
	if homebrew(exePath) {
		return "Run: brew upgrade basaltdbhq/tap/basaltdb"
	}
	return "Get it at " + n.URL
}

// AgentMessage is the notice as an agent should read it: a WARNING: or
// SECURITY UPDATE: prefix instead of color, what to tell the person, the
// upgrade step, and the rule that the agent never upgrades on its own.
func (n Notice) AgentMessage(exePath string) string {
	prefix := "WARNING:"
	if n.Security {
		prefix = "SECURITY UPDATE:"
	}
	return fmt.Sprintf("%s BasaltDB %s is out of date; %s is available. Tell the person now. %s. "+
		"Do not upgrade it yourself unless the person says yes.", prefix, n.Current, n.Latest, n.upgradeSentence(exePath))
}

func (n Notice) upgradeSentence(exePath string) string {
	if homebrew(exePath) {
		return "They upgrade with: brew upgrade basaltdbhq/tap/basaltdb, then restart the engine so it runs the new binary"
	}
	return "They get the new release at " + n.URL + " and then restart the engine so it runs the new binary"
}

// homebrew reports whether the binary at exePath, symlinks resolved, sits in
// a Homebrew prefix: a Cellar, or the Apple-silicon or Linux prefix.
func homebrew(exePath string) bool {
	paths := []string{exePath}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		paths = append(paths, resolved)
	}
	for _, p := range paths {
		if strings.Contains(p, "/Cellar/") || strings.Contains(p, "/opt/homebrew/") || strings.Contains(p, "/home/linuxbrew/.linuxbrew/") {
			return true
		}
	}
	return false
}

// Line is the one-line notice for a terminal or a log.
func (n Notice) Line(exePath string) string {
	kind := "is out of date"
	if n.Security {
		kind = "is out of date (SECURITY UPDATE)"
	}
	return fmt.Sprintf("basalt %s %s; %s is available. %s", n.Current, kind, n.Latest, n.UpgradeHint(exePath))
}
