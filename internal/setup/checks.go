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
