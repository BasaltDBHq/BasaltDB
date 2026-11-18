package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

func linkIO(tty bool) (*cliIO, *bytes.Buffer) {
	var out bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &out, err: io.Discard},
		func(string) string { return "" })
	c.tty = func(io.Writer) bool { return tty }
	return c, &out
}

// badBases are bases with a control byte after the 21-byte
// "http://localhost:8787": ESC, BEL, newline, DEL and U+009B (CSI).
var badBases = map[string]string{
	"ESC":    "http://localhost:8787\x1b[31m",
	"BEL":    "http://localhost:8787\x07",
	"LF":     "http://localhost:8787\n",
	"DEL":    "http://localhost:8787\x7f",
	"U+009B": "http://localhost:8787\u009b",
}

const firstBadPosition = "character 22"

func requirePrintable(t *testing.T, name, msg string) {
	t.Helper()
	for _, b := range []byte(msg) {
		require.True(t, b >= 0x20 && b < 0x7f, name+": the message echoes a control or non-ASCII byte")
	}
}

func TestPrintLinkHyperlinkOnlyOnATerminal(t *testing.T) {
	t.Parallel()
	const link = "http://localhost:8787/approvals/0190a3f2-7c1e-7000-8000-000000000001#1.abc"
	c, out := linkIO(true)
	require.NoError(t, printLink(c, out, link, linkRef{}))
	require.Equal(t, "\x1b]8;;"+link+"\x1b\\"+link+"\x1b]8;;\x1b\\\n", out.String())

	c, out = linkIO(false)
	require.NoError(t, printLink(c, out, link, linkRef{}))
	require.Equal(t, link+"\n", out.String(), "a pipe gets the plain URL")
}

func TestIsTerminalNeedsATerminalFile(t *testing.T) {
	t.Parallel()
	c, out := linkIO(false)
	c.tty = nil
	require.False(t, c.isTerminal(out), "a buffer is not a terminal")
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer f.Close()
	require.False(t, c.isTerminal(f), "a device that is not a tty")
}

func TestPrintLinkRefusesABadURLWithoutWritingIt(t *testing.T) {
	t.Parallel()
	for name, base := range badBases {
		c, out := linkIO(true)
		err := printLink(c, out, base+"/approvals/x", linkRef{setting: "pagesUrl", item: "approval 0190", again: "basalt approve --show 0190"})
		require.Error(t, err, name)
		require.Empty(t, out.String(), name+": nothing of the URL or a control byte is written")
		msg := err.Error()
		require.Contains(t, msg, "pagesUrl", name)
		require.Contains(t, msg, "approval 0190", name)
		require.Contains(t, msg, firstBadPosition, name)
		require.Contains(t, msg, "basalt approve --show 0190", name)
		requirePrintable(t, name, msg)

		var errOut bytes.Buffer
		c.stderr = &errOut
		require.Equal(t, exitError, c.fail(err), name)
		requirePrintable(t, name, strings.TrimSuffix(errOut.String(), "\n"))
	}
}

func TestPagesURLFlagRefusesABadBaseAsUsage(t *testing.T) {
	t.Parallel()
	const id = "0190a3f2-7c1e-7000-8000-000000000001"
	for name, base := range badBases {
		r := cli(t, nil, "", "approve", "--pages-url", base, "--show", id)
		require.Equal(t, exitUsage, r.code, name)
		require.Contains(t, r.stderr, "--pages-url", name)
		require.Contains(t, r.stderr, firstBadPosition, name)
		for _, raw := range []string{"\x1b", "\x07", "\x7f", "\u009b"} {
			require.NotContains(t, r.stdout+r.stderr, raw, name)
		}
	}
	for _, base := range []string{"ftp://x", "http://example.com", "http://localhost:8787/?a=b", "https://example.com/#x"} {
		r := cli(t, nil, "", "approve", "--pages-url", base, "--show", id)
		require.Equal(t, exitUsage, r.code, base)
	}
}

func TestConfigLoadRefusesABadPagesURL(t *testing.T) {
	t.Parallel()
	for name, base := range badBases {
		quoted, err := json.Marshal(base)
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "engine.json")
		body := `{"socketDir": "/tmp/bt", "pagesUrl": ` + string(quoted) + `,
			"agents": [{"name": "bot", "osUser": "tester", "store": {"kind": "POSTGRES", "credentialFile": "/tmp/cred"}}]}`
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		_, err = config.Load(path)
		require.Error(t, err, name)
		require.Contains(t, err.Error(), "pagesUrl", name)
		require.Contains(t, err.Error(), firstBadPosition, name)
		requirePrintable(t, name, strings.ReplaceAll(err.Error(), path, ""))
	}
}

func TestPagesURLFlagRefusesCredentialsAndBadPorts(t *testing.T) {
	t.Parallel()
	for _, base := range []string{"http://localhost:80@evil.com", "http://[::1]:1@evil.com", "http://localhost:abc", "https://evil.com@x"} {
		r := cli(t, nil, "", "approve", "--pages-url", base, "--show", "0190a3f2-7c1e-7000-8000-000000000001")
		require.Equal(t, exitUsage, r.code, base)
	}
}

func TestPrintableLabel(t *testing.T) {
	t.Parallel()
	require.Equal(t, "a?b?c?d?", printableLabel("a\x1bb\nc\u009bd\x07"))
}

// The local pages run only at localhost, so --pages-url on a loopback IP is
// a usage error naming the localhost base to use instead.
func TestPagesURLFlagRefusesALoopbackIP(t *testing.T) {
	t.Parallel()
	for base, want := range map[string]string{
		"http://127.0.0.1:8787": "use http://localhost:8787",
		"http://[::1]:9000":     "use http://localhost:9000",
	} {
		r := cli(t, nil, "", "approve", "--pages-url", base, "--show", "0190a3f2-7c1e-7000-8000-000000000001")
		require.Equal(t, exitUsage, r.code, base)
		require.Contains(t, r.stderr, want, base)
	}
}
