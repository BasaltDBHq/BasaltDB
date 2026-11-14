//go:build !unix

package web_test

import "os/exec"

// killGroupOnCancel keeps exec's default Cancel (kill the main process):
// without process groups, cmd.WaitDelay bounds the wait for its output.
func killGroupOnCancel(*exec.Cmd) {}
