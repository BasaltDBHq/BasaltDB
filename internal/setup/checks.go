package setup

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// EnvAdminURL is the environment variable that would carry an admin
// connection string; init never reads it.
const EnvAdminURL = "BASALT_ADMIN_DATABASE_URL"

// RemoteAdminEnvSet is basalt init --remote's warning when
// BASALT_ADMIN_DATABASE_URL is set: it never uses it, and an agent on this
// machine may read it.
const RemoteAdminEnvSet = EnvAdminURL + " is set here; basalt init --remote never uses it. " +
	"If an agent can read this environment, remove it and ask the person to change that database password now."

// RefuseSecretInitArgs refuses --init-arg values that look like a
// connection string or carry a password. None is saved or replayed.
func RefuseSecretInitArgs(args []string) error {
	for _, a := range args {
		lower := strings.ToLower(a)
		if strings.Contains(lower, "password=") {
			return fmt.Errorf("saved init argument %q carries a password", a)
		}
		if _, rest, ok := strings.Cut(a, "://"); ok && strings.Contains(rest, "@") {
			return fmt.Errorf("saved init argument %q looks like a connection string", a)
		}
	}
	return nil
}

// CheckServicePersons refuses a service install without a person uid, or
// with root or the engine's own OS user among them (CONTRACT.md, CLI,
// Recording the person).
func CheckServicePersons(uids []uint32, engineUser string) error {
	if err := CheckPersons(uids); err != nil {
		return err
	}
	u, err := user.Lookup(engineUser)
	if err != nil {
		return nil //nolint:nilerr // the engine's user does not exist yet: the install creates it, with a new uid
	}
	for _, uid := range uids {
		if strconv.FormatUint(uint64(uid), 10) == u.Uid {
			return fmt.Errorf("--person-uid %d is the engine's own OS user %s; give the person's", uid, engineUser)
		}
	}
	return nil
}

// Cli is what the setup checks reach of the CLI's own rules: the refusal of
// an agent's OS user carries the CLI's usage error.
type Cli interface {
	// CheckAgentOSUserWith refuses an agent's OS user that is the engine's
	// own user or is in the engine's group, looking groups up through the
	// two functions.
	CheckAgentOSUserWith(osUser, engineUser string, lookupGroup func(string) (*user.Group, error),
		groups func(string) ([]string, error)) error
}

// CheckAgentOSUser refuses an agent's OS user that is the engine's own
// user or is in the engine's group (named as the engine's user): that
// group reaches every plugin socket in service mode, and the engine's
// config directory. When the group does not exist yet (the install makes
// it), no one is in it. A lookup that fails otherwise refuses.
func CheckAgentOSUser(c Cli, osUser, engineUser string) error {
	return c.CheckAgentOSUserWith(osUser, engineUser, user.LookupGroup, osUserGroups)
}

// osUserGroups are an OS user's group ids, its primary group included.
func osUserGroups(name string) ([]string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	return append(gids, u.Gid), nil
}
