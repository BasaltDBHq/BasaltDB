package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/basaltdbhq/basaltdb/internal/updatecheck"
)

func TestPrintUpdateLine(t *testing.T) {
	n := &updatecheck.Notice{Current: "0.0.1", Latest: "0.0.2", URL: "u"}
	var b bytes.Buffer
	printUpdateLine(&b, func(string) string { return "" }, n, "/x/basalt")
	if got := b.String(); strings.Contains(got, "\x1b") || !strings.Contains(got, "basalt 0.0.1 is out of date; 0.0.2 is available.") || !strings.HasSuffix(got, "\n") {
		t.Errorf("non-terminal output = %q", got)
	}
	b.Reset()
	printUpdateLine(&b, func(string) string { return "" }, nil, "/x/basalt")
	if b.Len() != 0 {
		t.Errorf("printed without a notice: %q", b.String())
	}
}

func TestStartUpdateNoticeSkips(t *testing.T) {
	// BASALT_CACHE_DIR points at an empty dir, so no notice could print
	// even if a command did not skip; the point is that no refresh starts
	// and nothing blocks. The off switch and skip list return at once.
	getenv := func(k string) string {
		if k == updatecheck.EnvDisable {
			return "off"
		}
		return ""
	}
	var e bytes.Buffer
	for _, args := range [][]string{nil, {"engine"}, {"mcp"}, {"status", "--json"}, {"version"}} {
		startUpdateNotice(context.Background(), args, stdio{err: &e}, getenv)()
	}
	if e.Len() != 0 {
		t.Errorf("printed %q", e.String())
	}
}
