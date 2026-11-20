package agent

import (
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// LabelConnect labels the connect link next to a personMessage
// (api/mcp/links/link.schema.json).
const LabelConnect = "Connect your database"

// ConnectLink is the connect link for a pending setup code, or "" when the
// engine hands none: budget is config.ConnectLinkBudget (0 unless the engine
// is agent-operated, the Vault is on and the pages are the portal's), and the
// whole link must fit it (CONTRACT.md, Connect, The connect link). There is
// no network call: the link only holds the code.
func ConnectLink(code string, budget int) string {
	if budget <= 0 || code == "" {
		return ""
	}
	url := links.ConnectURL(code)
	if len(url) > budget {
		return ""
	}
	return url
}

// ConnectMessage is the personMessage that hands the person the connect
// link first and the laptop command second. lead says what is pending; it
// names the Basalt Vault, a hosted service, as what the link uses. The
// command stays in the PERSON step the agent shows, in full.
func ConnectMessage(lead, url, fingerprint string) (string, []mcp.Link) {
	return newMessage().
		Text(lead+" Open this link and follow the page, and check that it shows the setup fingerprint "+fingerprint+". The link uses Basalt Vault, a hosted service, to run the setup once:").
		Link(LabelConnect, url).
		Text("Or, to use no hosted service, run the basalt init --setup-code command the agent shows you on your own computer. Then tell the agent it is done. Never paste your database password into this chat.").
		Build()
}

// ConnectStepText is the text of the PERSON OPEN_LINK step of a pending
// setup.
const ConnectStepText = "Open the link on your own computer or phone, check that it shows the same setup fingerprint and follow the page. It uses Basalt Vault, a hosted service."
