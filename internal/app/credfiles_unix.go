//go:build unix

package app

import (
	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/handoff/out/handofffiles"
)

// openRootFiles opens the files of agent for a root engine
// (handofffiles.RootFiles): credFile must be the computed agents/<agent>.url
// (handoff.RootCredentialPath).
func openRootFiles(configPath, agent, credFile string) (handoff.AgentFiles, error) {
	path, err := handoff.RootCredentialPath(configPath, agent, credFile)
	if err != nil {
		return nil, err
	}
	files, err := handofffiles.OpenRootFiles(configPath, path)
	if err != nil {
		return nil, err
	}
	return files, nil
}
