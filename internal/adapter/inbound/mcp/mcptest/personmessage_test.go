package mcptest_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp/mcptest"
)

const url = "http://localhost:8787/approvals/x#s=abc"

var link = []mcp.Link{{Label: "Approve the held write", URL: url}}

func TestProblemAcceptsWhatTheContractAllows(t *testing.T) {
	t.Parallel()
	require.NoError(t, mcptest.Problem("Approve:\n\n"+url+"\n\nThen wait.", link))
	require.NoError(t, mcptest.Problem("Approve:\n\n"+url, link))
	require.NoError(t, mcptest.Problem("No link here.", nil))
	require.NoError(t, mcptest.Problem(strings.Repeat("a", mcptest.PersonMessageLimit), nil))
	long := "http://localhost:8787/reverts/y#2." + strings.Repeat("A", 5000)
	require.NoError(t, mcptest.Problem("Sign:\n\n"+long, []mcp.Link{{Label: "Review and sign the revert", URL: long}}),
		"a URL line is not counted, whatever its length")
}

func TestProblemFindsEveryBrokenRule(t *testing.T) {
	t.Parallel()
	for name, bad := range map[string]struct {
		message string
		links   []mcp.Link
	}{
		"a URL in the middle of a line": {"Approve " + url + " now", link},
		"no blank line before":          {"Approve:\n" + url + "\n\nThen.", link},
		"no blank line after":           {"Approve:\n\n" + url + "\nThen.", link},
		"a stop after the URL":          {"Approve:\n\n" + url + ".", link},
		"a Markdown link":               {"Approve [here](" + url + ")", link},
		"a carriage return":             {"Approve:\r\n\r\n" + url, link},
		"links missing":                 {"Approve:\n\n" + url, nil},
		"links without a URL":           {"Nothing to open.", link},
		"links without a message":       {"", link},
		"another URL in links":          {"Approve:\n\n" + url, []mcp.Link{{Label: "Approve", URL: url + "x"}}},
		"a label with Markdown":         {"Approve:\n\n" + url, []mcp.Link{{Label: "[Approve]", URL: url}}},
		"an empty label":                {"Approve:\n\n" + url, []mcp.Link{{URL: url}}},
		"a label over 80 characters":    {"Approve:\n\n" + url, []mcp.Link{{Label: strings.Repeat("a", 81), URL: url}}},
		"over 500 characters":           {strings.Repeat("a", mcptest.PersonMessageLimit+1), nil},
		"over 500 around a URL":         {strings.Repeat("a", 300) + "\n\n" + url + "\n\n" + strings.Repeat("b", 300), link},
	} {
		require.Error(t, mcptest.Problem(bad.message, bad.links), name)
	}
}
