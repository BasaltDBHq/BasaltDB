package setup

import (
	"errors"
	"os"
)

// A removed engine (CONTRACT.md, The local setup page, Removing the engine
// service): a REMOVE deleted engine.json with the engine's last agent and
// created the removal job's marker, and the engine still runs, serving no
// agent, until that job stops it. An INSTALL on it runs as a first install
// does (basalt init --demo after a removal).

// removed: this engine runs with a config, and a REMOVE deleted it.
func (s *LocalService) removed() bool {
	return s.opts.Configured && errors.Is(s.be.Lstat(s.opts.ConfigPath), os.ErrNotExist)
}

// installOnRemoved: req is an INSTALL on a removed engine, which runs as on
// an engine with no config (validate refuses it once engine.json exists
// again).
func (s *LocalService) installOnRemoved(req Request) bool {
	return req.Job == JobInstall && s.removed()
}

// StateDir is where an install records the engine's key: on a removed
// engine too, whose INSTALL plans as a first install does (the key, and
// the demo's policies on tables it reuses).
func (s *LocalService) StateDir() string { return s.opts.StateDir }
