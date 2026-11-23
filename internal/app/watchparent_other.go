//go:build !unix

package app

import "context"

func watchSupervisedParent(context.Context) {}
