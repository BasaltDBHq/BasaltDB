//go:build !unix

package main

// fileOwner is unknown off Unix: the engine runs on Linux and macOS only.
func fileOwner(string) string { return "" }
