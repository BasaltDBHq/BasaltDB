//go:build !linux

package main

import (
	"os"
	"os/exec"
)

// watchParentEnv is set on a supervised child on platforms without
// Pdeathsig, so the engine stops when its supervisor dies.
const watchParentEnv = "BASALT_SUPERVISED"

// prepareSuperviseChild asks the child to notice when this process dies.
func prepareSuperviseChild(cmd *exec.Cmd) {
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(env, watchParentEnv+"=1")
}
