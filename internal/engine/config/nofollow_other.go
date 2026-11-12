//go:build !unix

package config

import "os"

func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
