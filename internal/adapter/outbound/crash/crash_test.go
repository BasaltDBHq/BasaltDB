package crash

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// leakedConn is built from parts so no secret scanner reads it as a
// committed credential.
var leakedConn = "postgres" + "://admin" + ":hunter2pass" + "@db.internal.example:5432/prod"

// secrets are values that must not survive into any saved report.
var secrets = []string{
	"SELECT email FROM customers WHERE ssn = '123-45-6789'",
	"customers_private_table",
	"ssn_column",
	"alice@example.com",
	leakedConn,
	"hunter2pass",
	"db.internal.example",
	"10.20.30.40",
	"/Users/alice/secret-project",
	"envsecretvalue99",
	"my-laptop-hostname",
}

func testRecorder(t *testing.T) Recorder {
	t.Helper()
	return Recorder{
		Dir: filepath.Join(t.TempDir(), DirName), Version: "1.2.3",
		Scrub: NewScrubber("/Users/alice", "my-laptop-hostname", []string{"PGPASSWORD=envsecretvalue99", "SHORT=ab"}),
		Now:   func() time.Time { return time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC) },
	}
}

// leak panics with every secret in the value, in an argument and in the
// call chain, and returns the stack as the handler sees it.
func leak(t *testing.T, value any) (stack []byte) {
	t.Helper()
	defer func() {
		if recover() != nil {
			stack = debug.Stack()
		}
	}()
	deep(strings.Join(secrets, " "), value)
	return nil
}

func deep(arg string, value any) {
	_ = arg
	panic(value)
}

func requireClean(t *testing.T, rep Report) {
	t.Helper()
	text := rep.Show()
	link, _ := rep.IssueURL()
	decoded, err := url.QueryUnescape(link)
	require.NoError(t, err)
	for _, s := range secrets {
		require.NotContains(t, text, s)
		require.NotContains(t, decoded, s)
	}
	require.NotContains(t, text, "/Users/alice")
	require.NotContains(t, text, "123-45-6789")
}

func TestPanicValuesAreNeverSaved(t *testing.T) {
	r := testRecorder(t)
	values := []any{
		strings.Join(secrets, " "),
		errors.New(strings.Join(secrets, " ")),
		fmt.Errorf("wrapped: %w", errors.New(secrets[0])),
		map[string]string{"k": secrets[1]},
		struct{ Row string }{secrets[3]},
	}
	for _, v := range values {
		rep, err := r.Save(Input{Command: "log", Kind: KindPanic, ErrorCode: "INTERNAL", Value: v, Stack: leak(t, v)})
		require.NoError(t, err)
		requireClean(t, rep)
		require.True(t, strings.HasPrefix(rep.Message, "panic value of type "), rep.Message)
	}
}

func TestRuntimeErrorMessageIsKeptAndScrubbed(t *testing.T) {
	r := testRecorder(t)
	var rtErr any
	func() {
		defer func() { rtErr = recover() }()
		xs := make([]int, 0, 1)
		i := 3
		_ = xs[:1][i]
	}()
	rep := r.Build(Input{Command: "log", Value: rtErr})
	require.Equal(t, "runtime error: index out of range [3] with length 1", rep.Message)

	// A runtime-error-shaped value that carries a secret is scrubbed.
	rep = r.Build(Input{Command: "log", Value: fakeRuntimeError(secrets[0])})
	require.Equal(t, "<redacted>", rep.Message)
	rep = r.Build(Input{Command: "log", Value: fakeRuntimeError("cannot reach " + secrets[4] + " as " + secrets[3])})
	for _, s := range secrets {
		require.NotContains(t, rep.Message, s)
	}
}

type fakeRuntimeError string

func (f fakeRuntimeError) Error() string { return string(f) }
func (f fakeRuntimeError) RuntimeError() {}

func TestCommandAndCodeAreAllowlisted(t *testing.T) {
	r := testRecorder(t)
	rep := r.Build(Input{Command: secrets[0], ErrorCode: secrets[1], Kind: "x"})
	require.Equal(t, "unknown", rep.Command)
	require.Empty(t, rep.ErrorCode)
	require.Equal(t, KindPanic, rep.Kind)

	rep = r.Build(Input{Command: "run_history", ErrorCode: "INTERNAL", Kind: KindFatal})
	require.Equal(t, "run_history", rep.Command)
	require.Equal(t, "INTERNAL", rep.ErrorCode)
	require.Equal(t, KindFatal, rep.Kind)
}

func TestStackKeepsShapeAndDropsValues(t *testing.T) {
	s := NewScrubber("/Users/alice", "my-laptop-hostname", []string{"X=envsecretvalue99"})
	raw := "goroutine 1 [running]:\n" +
		"runtime/debug.Stack()\n\t/usr/local/go/src/runtime/debug/stack.go:26 +0x5e\n" +
		"main.run({0xc000012345, 0x1c}, {0x1400, 0x9})\n\t/Users/alice/secret-project/BasaltDB/cmd/basalt/main.go:73 +0x1d\n" +
		"panic: SELECT ssn_column FROM customers_private_table\n" +
		"main.(*T).m(0x1)\n\t/Users/alice/go/pkg/mod/github.com/x/y@v1.0.0/z.go:9 +0x1\n" +
		"created by main.start in goroutine 7\n\t/home/bob/src/a/b/c/d.go:5 +0x2\n"
	out := s.Stack(raw)
	require.Contains(t, out, "goroutine 1 [running]:")
	require.Contains(t, out, "main.run(...)")
	require.Contains(t, out, "\tcmd/basalt/main.go:73")
	require.Contains(t, out, "main.(*T).m(...)")
	require.Contains(t, out, "created by main.start")
	require.Contains(t, out, "\tb/c/d.go:5")
	for _, bad := range []string{"0xc000012345", "SELECT", "ssn_column", "Users/alice", "secret-project", "/home/bob", "+0x"} {
		require.NotContains(t, out, bad)
	}
}

func TestTextScrubbing(t *testing.T) {
	s := NewScrubber("/Users/alice", "my-laptop-hostname", []string{"K=envsecretvalue99"})
	in := "dial " + leakedConn + "; host=db.internal.example password=hunter2pass " +
		"alice@example.com 10.20.30.40:5432 ::1 fe80::1 /Users/alice/x my-laptop-hostname envsecretvalue99 'quoted row value'"
	out := s.Text(in)
	for _, bad := range []string{"hunter2pass", "db.internal.example", "alice@example.com", "10.20.30.40", "fe80::1", "/Users/alice", "my-laptop-hostname", "envsecretvalue99", "quoted row value"} {
		require.NotContains(t, out, bad)
	}
}

func TestStackIsBoundedAndIssueLinkFits(t *testing.T) {
	r := testRecorder(t)
	var b strings.Builder
	b.WriteString("goroutine 1 [running]:\n")
	for i := range 2000 {
		fmt.Fprintf(&b, "main.f%d(0x1)\n\t/src/pkg/dir/file%d.go:%d +0x1\n", i, i, i)
	}
	rep := r.Build(Input{Command: "log", Stack: []byte(b.String())})
	require.LessOrEqual(t, len(rep.Stack), maxStack+len("\n...trimmed..."))
	link, trimmed := rep.IssueURL()
	require.True(t, trimmed)
	require.LessOrEqual(t, len(link), maxURL)
	require.True(t, strings.HasPrefix(link, IssueBase+"?"))
	u, err := url.Parse(link)
	require.NoError(t, err)
	require.Contains(t, u.Query().Get("body"), "main.f0(...)")
	require.Contains(t, u.Query().Get("body"), "stack trimmed")
	require.Equal(t, "crash(log): panic in 1.2.3", u.Query().Get("title"))

	short, trimmed := r.Build(Input{Command: "log", Stack: []byte("goroutine 1 [running]:\nmain.x()\n\tf.go:1 +0x1\n")}).IssueURL()
	require.False(t, trimmed)
	require.Contains(t, short, "title=")
}

func TestEnvValuesDoNotMangleFunctionNames(t *testing.T) {
	s := NewScrubber("/Users/alice", "", []string{"USER=basalt"})
	out := s.Stack("goroutine 1 [running]:\ngithub.com/basaltdbhq/basaltdb/cmd/basalt.run(0x1)\n\t/src/basalt/cmd/basalt/main.go:7 +0x1\n")
	require.Contains(t, out, "github.com/basaltdbhq/basaltdb/cmd/basalt.run(...)")
}

func TestTamperedReportIsSkipped(t *testing.T) {
	r := testRecorder(t)
	rep, err := r.Save(Input{Command: "log", Value: "x"})
	require.NoError(t, err)
	rep.Command = "\x1b[31mred"
	raw := []byte(rep.Show())
	require.NoError(t, os.WriteFile(filepath.Join(r.Dir, rep.ID+".json"), raw, fileMode))
	require.Empty(t, List(r.Dir))
}

func TestIssueURLWithinCutsTheStackToTheLimit(t *testing.T) {
	t.Parallel()
	rep := Report{ID: "i", Version: "v1", Command: "query", ErrorCode: "INTERNAL", Stack: strings.Repeat("main.f()\n\t/src/a.go:1 +0x1\n", 400)}
	link, trimmed, ok := rep.IssueURLWithin(1800)
	require.True(t, ok)
	require.True(t, trimmed)
	require.LessOrEqual(t, len(link), 1800)
	whole, _ := rep.IssueURL()
	require.Greater(t, len(whole), 1800)
}

func TestIssueURLWithinFitsTheBudgetForTheWorstReport(t *testing.T) {
	t.Parallel()
	// Every field at its bound, and a stack of characters that each become
	// three characters in the link.
	rep := Report{
		ID: strings.Repeat("a", 36), Version: strings.Repeat("v", maxField), Command: strings.Repeat("c", 40),
		OS: strings.Repeat("o", maxField), Arch: strings.Repeat("a", maxField), GoVersion: strings.Repeat("g", maxField),
		ErrorCode: strings.Repeat("E", maxField), Message: strings.Repeat("é", maxMessage/2),
		Stack: strings.Repeat("é <>&\n", 3000),
	}
	for _, limit := range []int{1800} {
		link, trimmed, ok := rep.IssueURLWithin(limit)
		require.True(t, ok)
		require.True(t, trimmed)
		require.LessOrEqual(t, len(link), limit)
	}
}

func TestIssueURLWithinLeavesTheLinkOutWhenNothingFits(t *testing.T) {
	t.Parallel()
	rep := Report{
		ID: strings.Repeat("a", 36), Version: strings.Repeat("v", maxField), Command: strings.Repeat("c", 40),
		OS: strings.Repeat("o", maxField), Arch: strings.Repeat("a", maxField), GoVersion: strings.Repeat("g", maxField),
		ErrorCode: strings.Repeat("E", maxField), Stack: strings.Repeat("é <>&\n", 3000),
	}
	link, trimmed, ok := rep.IssueURLWithin(1000)
	require.Empty(t, link)
	require.False(t, trimmed)
	require.False(t, ok)
	whole, _ := rep.IssueURL()
	require.NotEmpty(t, whole, "the CLI link is unchanged")
}
