package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompare(t *testing.T) {
	order := []string{"0.0.1-alpha.1", "0.0.1-alpha.2", "0.0.1-alpha.10", "0.0.1-beta", "0.0.1", "0.0.2", "0.1.0", "1.0.0"}
	for i := range order {
		for j := range order {
			a, _ := parseVersion(order[i])
			b, _ := parseVersion(order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.compare(b); got != want {
				t.Errorf("%s vs %s = %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	for _, bad := range []string{"", "1.2", "dev", "1.2.x", "1.2.3-", "v1.2.3.4"} {
		if _, ok := parseVersion(bad); ok {
			t.Errorf("parseVersion(%q) accepted", bad)
		}
	}
	if v, ok := parseVersion("v1.2.3+build5"); !ok || v.core != [3]uint64{1, 2, 3} {
		t.Errorf("v1.2.3+build5 = %v %v", v, ok)
	}
}

func TestNotice(t *testing.T) {
	rels := []Release{
		{Tag: "v0.0.2-alpha.1", Prerelease: true},
		{Tag: "v0.0.1"},
		{Tag: "v0.0.1-alpha.2", Prerelease: true},
		{Tag: "v0.0.2", Security: true},
	}
	tests := []struct {
		name, current, latest string
		security, none        bool
	}{
		{name: "stable sees stable only", current: "0.0.1", latest: "0.0.2", security: true},
		{name: "prerelease sees newer prerelease and stable", current: "0.0.1-alpha.1", latest: "0.0.2", security: true},
		{name: "up to date", current: "0.0.2", none: true},
		{name: "ahead", current: "0.1.0", none: true},
		{name: "dev build", current: DevVersion, none: true},
		{name: "unparseable", current: "abc", none: true},
		{name: "v prefix", current: "v0.0.1", latest: "0.0.2", security: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := notice(tc.current, rels)
			if tc.none {
				if n != nil {
					t.Fatalf("got %+v", n)
				}
				return
			}
			if n == nil || n.Latest != tc.latest || n.Security != tc.security {
				t.Fatalf("got %+v", n)
			}
		})
	}
	// A stable user is not shown a pre-release only.
	if n := notice("0.0.1", []Release{{Tag: "v0.0.2-alpha.1", Prerelease: true}}); n != nil {
		t.Errorf("stable user got a pre-release: %+v", n)
	}
	// Security only counts for releases newer than the current one.
	if n := notice("0.0.2", []Release{{Tag: "v0.0.2", Security: true}, {Tag: "v0.0.3"}}); n == nil || n.Security {
		t.Errorf("old security release flagged: %+v", n)
	}
}

func TestMarkedSecurity(t *testing.T) {
	if !markedSecurity("Notes\n  Security: fixes the guard\n") || !markedSecurity("security: x") {
		t.Error("marker not found")
	}
	if markedSecurity("This has no security fix.\nSee Security: later") {
		t.Error("false positive")
	}
}

func TestRefreshOncePerDayAndShape(t *testing.T) {
	var hits atomic.Int32
	var agent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		agent = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`[{"tag_name":"v0.0.2","body":"Security: fix","prerelease":false},{"tag_name":"v0.0.3","draft":true}]`))
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	c := &Checker{Dir: t.TempDir(), Current: "0.0.1", URL: srv.URL, Now: func() time.Time { return now }}
	if c.Cached() != nil {
		t.Fatal("notice without a cache")
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := c.Cached()
	if n == nil || n.Latest != "0.0.2" || !n.Security || !strings.HasSuffix(n.URL, "/v0.0.2") {
		t.Fatalf("notice = %+v", n)
	}
	if agent != "basalt/0.0.1" {
		t.Errorf("User-Agent = %q", agent)
	}
	now = now.Add(23 * time.Hour)
	_ = c.Refresh(context.Background())
	if hits.Load() != 1 {
		t.Fatalf("asked %d times within a day", hits.Load())
	}
	now = now.Add(2 * time.Hour)
	_ = c.Refresh(context.Background())
	if hits.Load() != 2 {
		t.Fatalf("asked %d times after a day", hits.Load())
	}
}

func TestRefreshFailureKeepsCacheAndBacksOff(t *testing.T) {
	ok := true
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if !ok {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`[{"tag_name":"v0.0.2"}]`))
	}))
	defer srv.Close()
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	c := &Checker{Dir: t.TempDir(), Current: "0.0.1", URL: srv.URL, Now: func() time.Time { return now }}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ok = false
	now = now.Add(25 * time.Hour)
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("failure not reported")
	}
	if c.Cached() == nil {
		t.Fatal("failed refresh dropped the cache")
	}
	before := hits.Load()
	now = now.Add(10 * time.Minute)
	_ = c.Refresh(context.Background())
	if hits.Load() != before {
		t.Fatal("retried within the hour")
	}
	now = now.Add(time.Hour)
	_ = c.Refresh(context.Background())
	if hits.Load() != before+1 {
		t.Fatal("did not retry after the hour")
	}
}

func TestRefreshTimeoutDoesNotHang(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(block)
	c := &Checker{Dir: t.TempDir(), Current: "0.0.1", URL: srv.URL}
	start := time.Now()
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("expected a timeout")
	}
	if d := time.Since(start); d > RequestTimeout+time.Second {
		t.Fatalf("took %s", d)
	}
}

func TestDisabled(t *testing.T) {
	for v, want := range map[string]bool{"": false, "on": false, "off": true, "OFF": true, "0": true, "false": true, "no": true} {
		if got := Disabled(func(string) string { return v }); got != want {
			t.Errorf("%q = %v", v, got)
		}
	}
}

func TestLine(t *testing.T) {
	n := Notice{Current: "0.0.1-alpha.2", Latest: "0.0.2", URL: "https://example.test/r"}
	if got := n.Line("/usr/local/bin/basalt"); got != "basalt 0.0.1-alpha.2 is out of date; 0.0.2 is available. Get it at https://example.test/r" {
		t.Errorf("line = %q", got)
	}
	n.Security = true
	if got := n.Line("/opt/homebrew/Cellar/basaltdb/0.0.1/bin/basalt"); !strings.Contains(got, "SECURITY UPDATE") || !strings.HasSuffix(got, "brew upgrade basaltdbhq/tap/basaltdb") {
		t.Errorf("line = %q", got)
	}
}
