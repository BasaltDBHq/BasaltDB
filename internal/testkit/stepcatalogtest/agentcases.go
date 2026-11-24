package stepcatalogtest

import "github.com/basaltdbhq/basaltdb/internal/core/toolresult"

// AgentWarningCodes are the codes of the warning cases the agent package
// runs on its own use case; the agent service's tests cover the rest of the
// catalog's warnings and require these beside their own.
func AgentWarningCodes() []string {
	return []string{toolresult.WarningRLSHidesRows}
}
