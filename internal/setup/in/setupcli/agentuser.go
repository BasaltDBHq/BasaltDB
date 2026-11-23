package setupcli

import (
	"errors"
	"fmt"
	"os/user"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

// CheckAgentOSUserWith refuses an agent's OS user that is the engine's own
// user or is in the engine's group (named as the engine's user): that
// group reaches every plugin socket in service mode, and the engine's
// config directory. When the group does not exist yet (the install makes
// it), no one is in it. A lookup that fails otherwise refuses.
func CheckAgentOSUserWith(osUser, engineUser string, lookupGroup func(string) (*user.Group, error),
	groups func(string) ([]string, error),
) error {
	if strings.HasPrefix(osUser, "basalt-plugin-") || strings.HasPrefix(osUser, "_basalt-plugin-") {
		return fmt.Errorf("%w: --os-user %s is named as a plugin's OS user; Basalt keeps those names for plugins", cli.ErrUsage, osUser)
	}
	if osUser == engineUser {
		return fmt.Errorf("%w: --os-user %s is the engine's own OS user; give the agent an OS user of its own", cli.ErrUsage, osUser)
	}
	g, err := lookupGroup(engineUser)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the engine's group %s cannot be looked up, so --os-user %s cannot be checked: %w", engineUser, osUser, err)
	}
	gids, err := groups(osUser)
	if err != nil {
		return fmt.Errorf("the groups of --os-user %s cannot be read, so it cannot be checked: %w", osUser, err)
	}
	if slices.Contains(gids, g.Gid) {
		return fmt.Errorf("%w: --os-user %s is in the engine's group %s, which reaches plugin sockets and the engine's config; "+
			"take it out of that group or give the agent another OS user", cli.ErrUsage, osUser, engineUser)
	}
	return nil
}
