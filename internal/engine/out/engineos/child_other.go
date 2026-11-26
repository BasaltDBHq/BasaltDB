//go:build !linux

package engineos

import (
	"os"
	"os/exec"
	"strconv"
)

// WatchParentEnv is set on a supervised child on platforms without Pdeathsig
// and carries the supervisor pid. The child exits if its parent is
// not that pid, which also covers a supervisor killed before the child started.
const WatchParentEnv = "BASALT_SUPERVISED"

// prepareChild asks the child to notice when this process dies.
func prepareChild(cmd *exec.Cmd) {
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(env, WatchParentEnv+"="+strconv.Itoa(os.Getpid())) //nolint:gocritic // env is os.Environ or the caller's own slice; the result is cmd.Env
}
