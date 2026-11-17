// Package updatecheck tells a person or an agent that a newer BasaltDB
// release is out. It asks the public GitHub releases list of
// BasaltDBHq/BasaltDB at most once a day, keeps the answer in a small cache
// file, and never makes a command wait on the network: callers read the
// cache (Cached) and refresh it on the side (Refresh). The request carries
// no data about the person, the machine or the database, only a User-Agent
// with this build's version.
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
	"strings"
	"time"
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

// notice picks the newest release above current that the person may see:
// pre-releases only when current is one.
func notice(current string, releases []Release) *Notice {
	cur, ok := parseVersion(current)
	if !ok || current == DevVersion {
		return nil
	}
	var best *Release
	var bestV version
	security := false
	for i := range releases {
		r := &releases[i]
		v, ok := parseVersion(r.Tag)
		if !ok || (v.prerelease() && !cur.prerelease()) || v.compare(cur) <= 0 {
			continue
		}
		security = security || r.Security
		if best == nil || v.compare(bestV) > 0 {
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
	tmp, err := os.CreateTemp(c.Dir, cacheFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(cacheFilePerm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), c.path())
}

// ErrNoDir is returned by CacheDir when no cache directory can be found.
var ErrNoDir = errors.New("no cache directory")

// CacheDir is override, or the user cache directory's basalt folder.
func CacheDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoDir, err)
	}
	return filepath.Join(base, "basalt"), nil
}

// UpgradeHint is how to get the new release: the brew command when the
// running binary sits in a Homebrew prefix, else the release page.
func (n Notice) UpgradeHint(exePath string) string {
	if strings.Contains(exePath, "/Cellar/") || strings.Contains(exePath, "/opt/homebrew/") {
		return "Run: brew upgrade basaltdbhq/tap/basaltdb"
	}
	return "Get it at " + n.URL
}

// Line is the one-line notice for a terminal or a log.
func (n Notice) Line(exePath string) string {
	kind := "is out of date"
	if n.Security {
		kind = "is out of date (SECURITY UPDATE)"
	}
	return fmt.Sprintf("basalt %s %s; %s is available. %s", n.Current, kind, n.Latest, n.UpgradeHint(exePath))
}
