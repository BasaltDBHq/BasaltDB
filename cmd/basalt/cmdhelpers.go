package main

import (
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
)

// configOrFallback is the config a person command reads: the --config value,
// or, when --config was not given, perUserConfigFallback of the default.
func configOrFallback(h host, fs *flag.FlagSet, path string) string {
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "config" })
	if given {
		return path
	}
	return perUserConfigFallback(h, path)
}

// perUserConfigFallback is the config a command reads when --config is not
// given: the system path, unless this is not root, nothing is installed
// there, and init left a config in the user's own config directory.
func perUserConfigFallback(h host, system string) string {
	if h.Euid() == 0 {
		return system
	}
	if _, err := os.Stat(system); !errors.Is(err, fs.ErrNotExist) {
		return system
	}
	base, err := h.UserConfigDir()
	if err != nil {
		return system
	}
	user := filepath.Join(base, perUserDirName, "engine.json")
	if _, err := os.Stat(user); err != nil {
		return system
	}
	return user
}
