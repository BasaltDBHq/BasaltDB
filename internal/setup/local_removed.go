package setup

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

// A removed engine (CONTRACT.md, The local setup page, Removing the engine
// service): a REMOVE deleted engine.json with the engine's last agent, and
// the engine still runs, serving no agent. basalt init opens the REMOVED
// link, whose page asks the person: set BasaltDB up again, an INSTALL this
// engine now runs as a first install, or remove the engine from this
// computer too. That answer leaves only a mark, in memory, that the
// waiting basalt init reads once and answers with the administrator
// dialog's removal script. Host and Origin can be forged on loopback, so
// the mark is worth only that dialog, which the person can close.

// JobRemoved is a link only: basalt init's link for a removed engine. The
// page offers "Set up BasaltDB again", which runs an INSTALL, and "Remove
// it from this computer too" (RemoveEngine); no request carries REMOVED.
const JobRemoved = "REMOVED"

// CodeRemoveAsked is the answer to basalt init's probe (a check with no
// job) once the person pressed "Remove it from this computer too": init
// then runs the removal script through the administrator dialog. It is
// answered once.
const CodeRemoveAsked = "REMOVE_ASKED"

// removeAskedFor is how long that press waits for basalt init to read it.
const removeAskedFor = 5 * time.Minute

// removeMark is the person's "Remove it from this computer too", until
// basalt init reads it.
type removeMark struct {
	mu sync.Mutex
	at time.Time
}

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

// removedProbe answers basalt init's probe (a check with no job) on a
// removed engine: REMOVE_ASKED once after the person's press, else
// ENGINE_REMOVED, as every other request but an INSTALL. run is a run's
// request, which never reads the press.
func (s *LocalService) removedProbe(req Request, run bool) error {
	if err := s.engineRemoved(); err == nil {
		return nil
	}
	if !run && req.Job == "" && s.removeAsked() {
		return refuse(CodeRemoveAsked, "You asked to remove BasaltDB from this computer too. basalt init asks for your computer's administrator password next, to remove the engine.")
	}
	return s.engineRemoved()
}

// RemoveEngine marks the person's "Remove it from this computer too" for
// basalt init. It changes no file and no database, and only a removed
// engine takes it.
func (s *LocalService) RemoveEngine(_ context.Context) error {
	if !s.removed() {
		return refuse(CodeJobUnavailable, "This engine is not removed: it is set up, or waits for a first install. Ask the agent for a new link.")
	}
	s.removing.mu.Lock()
	s.removing.at = s.opts.Now()
	s.removing.mu.Unlock()
	return nil
}

// removeAsked reads the mark once: true when the person pressed within
// removeAskedFor.
func (s *LocalService) removeAsked() bool {
	s.removing.mu.Lock()
	defer s.removing.mu.Unlock()
	at := s.removing.at
	s.removing.at = time.Time{}
	return !at.IsZero() && s.opts.Now().Sub(at) < removeAskedFor
}

// StateDir is where an install records the engine's key: on a removed
// engine too, whose INSTALL plans as a first install does (the key, and
// the demo's policies on tables it reuses).
func (s *LocalService) StateDir() string { return s.opts.StateDir }
