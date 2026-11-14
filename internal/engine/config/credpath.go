package config

import (
	"fmt"
	"path/filepath"
)

// RootCredentialPath is the only credential file a root process (basalt
// init --remote, basalt engine without --user) reads and writes for agent:
// agents/<agent>.url next to configPath, absolute, where basalt init puts
// it. The config may belong to its directory's owner, the engine's user,
// who must not be able to send root's credential reads and writes to
// another file, such as another agent's credential or a file only root
// reads. named is the agent's credentialFile: a spelling of the same path
// (agents/sub/../bot.url) is accepted, and the computed path is returned
// for the caller to use instead of named. Anything else is a
// *CredentialPathError.
func RootCredentialPath(configPath, agent, named string) (string, error) {
	want, err := filepath.Abs(filepath.Join(filepath.Dir(configPath), "agents", agent+".url"))
	if err != nil {
		return "", err
	}
	got, err := filepath.Abs(named)
	if err != nil {
		return "", err
	}
	if got != want {
		return "", &CredentialPathError{Named: named, Want: want}
	}
	return want, nil
}

// CredentialPathError is a credentialFile a root process refuses: Named is
// the config's, Want where basalt init puts it. Callers add what to do.
type CredentialPathError struct{ Named, Want string }

func (e *CredentialPathError) Error() string {
	return fmt.Sprintf("the config names the credential file %s, not %s where basalt init puts it", e.Named, e.Want)
}
