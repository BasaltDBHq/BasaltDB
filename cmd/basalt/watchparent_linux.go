//go:build linux

package main

import "context"

// watchSupervisedParent is a no-op on Linux: the supervisor sets Pdeathsig.
func watchSupervisedParent(context.Context) {}
