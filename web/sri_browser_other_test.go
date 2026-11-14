//go:build !unix

package web_test

import "os/exec"

// killGroupOnCancel leaves cmd as it is: without process groups, the context
// kills the main process and cmd.WaitDelay bounds the wait for its output.
func killGroupOnCancel(*exec.Cmd) {}
