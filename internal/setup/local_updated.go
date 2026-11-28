package setup

import (
	"sync"
	"time"
)

// A finished Update for basalt init (CONTRACT.md, The local setup page,
// Removing the engine service): the basalt init that opened the CHANGE
// link waits for the page's Remove, and ends at once when the page's
// UPDATE for its agent finished, the job whose done screen tells the
// person to let the agent go on. Its probe names the agent and when it
// opened the link, so an Update that finished before, for an earlier
// init, does not end it.

// CodeGuardUpdated is the answer to basalt init's probe (a check with no
// job that names an agent and since) once an UPDATE for that agent
// finished after since.
const CodeGuardUpdated = "GUARD_UPDATED"

// CodeAgentRemoved is the answer to that probe once a REMOVE that left the
// engine other agents removed that agent after since: the engine stays, so
// no ENGINE_REMOVED comes, and the waiting init ends at once.
const CodeAgentRemoved = "AGENT_REMOVED"

// updateMarks are when each agent's last UPDATE finished, and when a
// REMOVE removed it, in the engine's memory only.
type updateMarks struct {
	mu      sync.Mutex
	at      map[string]time.Time
	removed map[string]time.Time
}

// markRemoved records that a REMOVE removed agents now.
func (s *LocalService) markRemoved(agents []string) {
	s.updated.mu.Lock()
	defer s.updated.mu.Unlock()
	if s.updated.removed == nil {
		s.updated.removed = map[string]time.Time{}
	}
	for _, a := range agents {
		s.updated.removed[a] = s.opts.Now()
	}
}

// removedSince: a REMOVE removed agent after since.
func (s *LocalService) removedSince(agent string, since time.Time) bool {
	s.updated.mu.Lock()
	defer s.updated.mu.Unlock()
	at, ok := s.updated.removed[agent]
	return ok && at.After(since)
}

// markUpdated records that agent's UPDATE finished now.
func (s *LocalService) markUpdated(agent string) {
	s.updated.mu.Lock()
	defer s.updated.mu.Unlock()
	if s.updated.at == nil {
		s.updated.at = map[string]time.Time{}
	}
	s.updated.at[agent] = s.opts.Now()
}

// updatedSince: an UPDATE for agent finished after since. It is not read
// once: every init waiting for that agent's page ends.
func (s *LocalService) updatedSince(agent string, since time.Time) bool {
	s.updated.mu.Lock()
	defer s.updated.mu.Unlock()
	at, ok := s.updated.at[agent]
	return ok && at.After(since)
}
