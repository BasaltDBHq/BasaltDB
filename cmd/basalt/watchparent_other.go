//go:build !unix

package main

import "context"

func watchSupervisedParent(context.Context) {}
