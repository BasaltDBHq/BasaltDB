package handoff

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// RootCredentialPath is the only credential file an engine running as root
// reads for agent: config.RootCredentialPath, agents/<agent>.url next to
// configPath.
func RootCredentialPath(configPath, agent, named string) (string, error) {
	path, err := config.RootCredentialPath(configPath, agent, named)
	if err != nil {
		return "", fmt.Errorf("%w; as root, basalt engine uses only that path. Fix the agent's store.credentialFile in the config, or start the engine as the agent's user", err)
	}
	return path, nil
}
