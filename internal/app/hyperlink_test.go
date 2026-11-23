package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

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
