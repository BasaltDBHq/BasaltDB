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
// link. lead says what is pending; it names the Basalt Vault, a hosted
// service, as what the link uses.
func ConnectMessage(lead, url, fingerprint string) (string, []mcp.Link) {
	return newMessage().
		Text(lead+" Open this link and follow the page, and check that it shows the setup fingerprint "+fingerprint+". The link uses Basalt Vault, a hosted service, to run the setup once:").
		Link(LabelConnect, url).
		Text("Then tell the agent it is done. Never paste your database password into this chat.").
		Build()
}

// ConnectStepText is the text of the PERSON OPEN_LINK step of a pending
// setup.
const ConnectStepText = "Open the link on your own computer or phone, check that it shows the same setup fingerprint and follow the page. It uses Basalt Vault, a hosted service."

// ConnectOnlyMessage is the personMessage of a connect-only setup code,
// which only the connect page runs (CONTRACT.md, Connect-only setup codes):
// the link, the fingerprint to check, and that the page asks for the
// database's connection string, which the agent never needs. No laptop
// command.
func ConnectOnlyMessage(lead, url, fingerprint string) (string, []mcp.Link) {
	return newMessage().
		Text(lead+" Open this link, check that it shows the setup fingerprint "+fingerprint+", and follow the page. It uses Basalt Vault, a hosted service:").
		Link(LabelConnect, url).
		Text("The page asks for your database's connection string: paste it there only. The agent never needs it, so never paste it into this chat.").
		Build()
}

// ConnectOnlyStepText is the text of the PERSON OPEN_LINK step of a pending
// connect-only setup.
const ConnectOnlyStepText = "Open the link on your own computer or phone, check that it shows the same setup fingerprint, and paste your database's connection string on that page only. It uses Basalt Vault, a hosted service."
