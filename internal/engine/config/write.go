package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

const (
	// FileMode is the mode of the config and credential files: the engine's
	// user only.
	FileMode = 0o600
	dirMode  = 0o700
)

// Settings are what basalt init writes besides the agent.
type Settings struct {
	// SocketDir and StateDir are used only when the config file is new.
	SocketDir, StateDir string
	// PagesURL replaces the config's pages base URL when set.
	PagesURL string
	// Mode replaces the config's mode when set.
	Mode Mode
	// PersonUIDs are added to the config's person uids; the recorded ones
	// stay (re-running init keeps them).
	PersonUIDs []uint32
}

// UpsertAgent adds agent a to the config at path, or replaces the agent of
// the same name, creating the file from s when it does not exist. basalt
// init calls it. The file is written atomically with FileMode.
func UpsertAgent(path string, s Settings, a Agent) error {
	raw, err := Upserted(path, s, a)
	if err != nil {
		return err
	}
	return WriteFile(path, raw)
}

// Upserted is the content UpsertAgent writes, without writing it: the
// service install writes it itself, owned by the engine's OS user.
func Upserted(path string, s Settings, a Agent) ([]byte, error) {
	c, err := Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		c = Config{SocketDir: s.SocketDir, StateDir: s.StateDir}
	case err != nil:
		return nil, err
	}
	if s.PagesURL != "" {
		c.PagesURL, c.ApprovalPage = s.PagesURL, ""
	}
	if s.Mode != "" {
		c.Mode = s.Mode
	}
	c.PersonUIDs = addUIDs(c.PersonUIDs, s.PersonUIDs)
	replaced := false
	for i := range c.Agents {
		if c.Agents[i].Name == a.Name {
			c.Agents[i], replaced = a, true
		}
	}
	if !replaced {
		c.Agents = append(c.Agents, a)
	}
	if err := validate.Struct(c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// WriteFile writes data to path atomically with FileMode, creating the
// directory (mode 0700) when missing.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".basalt-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(FileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// addUIDs is have with every uid of add it lacks, in order.
func addUIDs(have, add []uint32) []uint32 {
	for _, u := range add {
		if !slices.Contains(have, u) {
			have = append(have, u)
		}
	}
	return have
}
