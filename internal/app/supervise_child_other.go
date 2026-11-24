//go:build !linux

package app

import (
	"os"
	"os/exec"
	"strconv"
)

// watchParentEnv is set on a supervised child on platforms without Pdeathsig
// and carries the supervisor pid. The child exits if its parent is
// not that pid, which also covers a supervisor killed before the child started.
const watchParentEnv = "BASALT_SUPERVISED"

// prepareSuperviseChild asks the child to notice when this process dies.
func prepareSuperviseChild(cmd *exec.Cmd) {
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(env, watchParentEnv+"="+strconv.Itoa(os.Getpid())) //nolint:gocritic // env is os.Environ or the caller's own slice; the result is cmd.Env
}
