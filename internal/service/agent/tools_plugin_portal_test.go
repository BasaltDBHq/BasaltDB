package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/vault"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// pluginRelay is the Vault link relay as request_plugin sees it: connected
// or not, and what a registration answers.
type pluginRelay struct {
	connected bool
	err       error
	tokens    int
}

func (r *pluginRelay) Connected() bool { return r.connected }

func (r *pluginRelay) Register(context.Context, channel.LinkToken, time.Time) error {
	r.tokens++
	return r.err
}

// portalPluginService is an agent-operated engine on the bot's computer
// (same-user, the portal's pages, no local pages) with the fake
// engine-kept plugins and a Vault relay.
func portalPluginService(t *testing.T, f *fakePluginRequests, r *pluginRelay, vaultState string) *Service {
	t.Helper()
	s := pluginService(t, f)
	s.Commands = s.Commands.OperatedBy(mcpcontract.OperatedByAgent)
	s.OperatedBy, s.SameUser = mcpcontract.OperatedByAgent, true
	s.PagesOrigin, s.PagesBase = "", links.Portal
	setApprovals(&s.Deps, originKeys{origins: []string{links.Portal}}) // a passkey that signs on the portal
	s.Relay = r
	s.Vault = fixedVault{VaultStatus{State: vaultState}}
	return s
}

// On the bot's computer request_plugin opens the approval and hands over
// the portal short link the Vault registered (CONTRACT.md, Plugin approval
// through the portal); the steps are the local link's.
func TestRequestPluginHandsOverThePortalLink(t *testing.T) {
	t.Parallel()
	f := &fakePluginRequests{opened: openedPlugin()}
	r := &pluginRelay{connected: true}
	out, err := callPlugin(t, portalPluginService(t, f, r, string(vault.StateConnected)), map[string]any{"source": "/home/bot/local-ner"}, uploadMeta())
	require.NoError(t, err)
	require.Len(t, f.opens, 1)
	require.Equal(t, 1, r.tokens, "the link's token is registered before it is handed over")
	require.Equal(t, PluginStatePending, out.State)
	require.True(t, strings.HasPrefix(out.ApprovalURL, links.Portal+"/plugins/"+casePluginApproval+"#s="), out.ApprovalURL)
	require.Contains(t, out.PersonMessage, "\n"+out.ApprovalURL+"\n")
	require.Equal(t, mcp.ActionOpenLink, out.NextSteps[0].Action)
	require.Equal(t, out.ApprovalURL, out.NextSteps[0].URL)
}

// Without a portal link the install, change and name forms are refused
// NO_PORTAL_LINK before anything is written, saying why; removal and the
// wait need no link.
func TestRequestPluginWithoutAPortalLink(t *testing.T) {
	t.Parallel()
	for state, why := range map[string]string{
		string(vault.StateOff):         "the Vault is off",
		string(vault.StateKeyError):    "key file is refused",
		string(vault.StateConnecting):  "no connection to the Vault right now (status shows vault CONNECTING)",
		string(vault.StateUnreachable): "no connection to the Vault right now (status shows vault UNREACHABLE)",
		string(vault.StateConnected):   "status shows vault and engineRecord",
	} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			for _, args := range []map[string]any{{"source": "/home/bot/local-ner"}, {"name": "local-ner"}} {
				f := &fakePluginRequests{opened: openedPlugin()}
				_, err := callPlugin(t, portalPluginService(t, f, &pluginRelay{}, state), args, uploadMeta())
				te := requireReason(t, err, codePluginRefused, ReasonPluginNoPortalLink)
				require.Contains(t, te.Message, why)
				require.Contains(t, te.Message, "Nothing was written")
				require.Empty(t, f.opens, "nothing is asked of the engine")
				if _, ok := args["source"]; ok {
					require.Equal(t, []uuid.UUID{uuid.MustParse(casePluginUpload)}, f.dropped, "the refused call's upload is dropped")
				}
			}
			f := &fakePluginRequests{states: []PluginApprovalState{{Name: "local-ner", Instance: "default", State: PluginStatePending}}}
			s := portalPluginService(t, f, &pluginRelay{}, state)
			_, err := callPlugin(t, s, map[string]any{"name": "local-ner", "remove": true}, nil)
			require.NoError(t, err)
			require.Equal(t, []string{"local-ner/default"}, f.removes)
			_, err = callPlugin(t, s, map[string]any{"approvalId": casePluginApproval, "waitForApproval": 0}, nil)
			require.NoError(t, err)
		})
	}
}

// A registration the Vault refuses after the approval was opened: the entry
// stays written and withheld, no link is handed over, and the name form
// opens a new approval later.
func TestRequestPluginRegistrationFailsAfterTheOpen(t *testing.T) {
	t.Parallel()
	f := &fakePluginRequests{opened: openedPlugin()}
	r := &pluginRelay{connected: true, err: errors.New("no OK within 5 seconds")}
	_, err := callPlugin(t, portalPluginService(t, f, r, string(vault.StateConnected)), map[string]any{"source": "/home/bot/local-ner"}, uploadMeta())
	te := requireReason(t, err, codePluginRefused, ReasonPluginNoPortalLink)
	require.Len(t, f.opens, 1, "the approval was opened")
	require.Contains(t, te.Message, "the Vault did not register the link")
	require.Contains(t, te.Message, "call request_plugin with name and instance")
	require.NotContains(t, te.Message, "http", "no link is handed over")
	require.NotContains(t, te.PersonMessage, links.Portal)
}

// With devLocalPages the agent-operated engine's own pages serve the
// plugin approval: the local short link, no Vault.
func TestRequestPluginDevLocalPages(t *testing.T) {
	t.Parallel()
	f := &fakePluginRequests{opened: openedPlugin()}
	r := &pluginRelay{}
	s := portalPluginService(t, f, r, string(vault.StateOff))
	s.DevLocalPages, s.PagesOrigin = true, "http://localhost:7878"
	out, err := callPlugin(t, s, map[string]any{"source": "/home/bot/local-ner"}, uploadMeta())
	require.NoError(t, err)
	require.Zero(t, r.tokens)
	require.True(t, strings.HasPrefix(out.ApprovalURL, "http://localhost:7878/plugins/"), out.ApprovalURL)
}

// The upload methods refuse where the tool would: no portal link, no upload.
func TestPluginUploadsRefusedWithoutAPortalLink(t *testing.T) {
	t.Parallel()
	s := portalPluginService(t, &fakePluginRequests{}, &pluginRelay{}, string(vault.StateOff))
	requireReason(t, s.PluginUploadsServed(), codePluginRefused, ReasonPluginNoPortalLink)
	s = portalPluginService(t, &fakePluginRequests{}, &pluginRelay{connected: true}, string(vault.StateConnected))
	require.NoError(t, s.PluginUploadsServed())
}
