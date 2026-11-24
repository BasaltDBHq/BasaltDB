//go:build linux

package app

import "context"

// watchSupervisedParent is a no-op on Linux: the supervisor sets Pdeathsig.
func watchSupervisedParent(context.Context) {}
