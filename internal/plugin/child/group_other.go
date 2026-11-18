//go:build !unix

package child

import "os/exec"

func setGroup(*exec.Cmd) {}

func killGroup(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
