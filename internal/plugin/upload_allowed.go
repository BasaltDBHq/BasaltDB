package plugin

import (
	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
)

// UploadAllowed reports whether basalt mcp uploads a request_plugin call's
// plugin folder to an engine that said in its hello answer it is operated
// by operatedBy, with local page origin pagesOrigin: a person operates it
// and it gave its local page origin, or an agent operates it (its approval
// link is the portal's).
func UploadAllowed(operatedBy, pagesOrigin string) bool {
	switch operatedBy {
	case mcpcontract.OperatedByPerson:
		return pagesOrigin != ""
	case mcpcontract.OperatedByAgent:
		return true
	}
	return false
}
