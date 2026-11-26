package connecttest

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// notFromTheService are the setup package's codes the connect service
// cannot get, so the contract's refusal table leaves them out.
var notFromTheService = map[string]string{
	setup.CodePasskeyNotRegistered: "needs RunInput.AskPasskey, the laptop's passkey step",
}

// Every code the setup package returns is a reason of the contract's
// refusal table, and this server answers it with the table's ConnectRPC
// code: a new package code fails here until the contract has its row.
func TestContractRefusalsCoverTheSetupPackage(t *testing.T) {
	t.Parallel()
	table := contractRefusals(t)
	for code := range notFromTheService {
		require.Contains(t, setup.Codes(), code, "an exemption the package no longer returns")
	}
	for _, code := range setup.Codes() {
		if _, ok := notFromTheService[code]; ok {
			require.NotContains(t, table, code, "%s is in the table: drop its exemption", code)
			continue
		}
		want, ok := table[code]
		require.True(t, ok, "the setup package returns %s, which contract/connect.md's refusal table lacks", code)
		got := fromSetup(&setup.Error{Code: code, Message: "m"})
		require.Equal(t, code, got.reason, code)
		require.Equal(t, want, got.code.String(), code)
	}
}

// contractRefusals reads the reason and ConnectRPC code of each row of
// contract/connect.md's refusal table.
func contractRefusals(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), "contract", "connect.md"))
	require.NoError(t, err)
	_, section, ok := strings.Cut(string(raw), "### Connect refusals\n")
	require.True(t, ok)
	section, _, _ = strings.Cut(section, "\n### ")
	codes := map[string]bool{}
	for c := connect.Code(1); c <= connect.CodeUnauthenticated; c++ {
		codes[c.String()] = true
	}
	tick := regexp.MustCompile("`([A-Z_]+)`")
	out := map[string]string{}
	for _, line := range strings.Split(section, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 4 || !strings.HasPrefix(strings.TrimSpace(cells[1]), "`") {
			continue
		}
		code := strings.Trim(strings.TrimSpace(cells[2]), "`")
		require.True(t, codes[code], "row %q: %q is not a ConnectRPC code", line, code)
		for _, m := range tick.FindAllStringSubmatch(cells[1], -1) {
			require.NotContains(t, out, m[1], "reason %s has two rows", m[1])
			out[m[1]] = code
		}
	}
	require.NotEmpty(t, out)
	return out
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for !slices.Contains([]string{"", "/"}, dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("no go.mod above the test")
	return ""
}
