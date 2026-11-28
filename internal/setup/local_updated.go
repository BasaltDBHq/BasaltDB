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

// CodeChangedPrefix starts the answer to that probe once a fix (a
// certificate, labels, a passkey added or removed, the agent's login)
// finished for that agent after since: CHANGED_ and the fix's job, as in
// FixJobs. Like GUARD_UPDATED it ends the waiting init at once, and every
// init waiting for that agent.
const CodeChangedPrefix = "CHANGED_"

// updateMarks are when each agent's last UPDATE finished, and when a
// REMOVE removed it, in the engine's memory only.
// Marks are the setup page's finished jobs, for basalt init's probe: when
// each agent's last UPDATE and fix finished and when a REMOVE removed it.
// The engine builds a new LocalService each time it serves its config again
// (after a fix rewrote a connection string, say), so the engine creates one
// Marks, keeps it in memory for its whole life and gives it to every
// LocalService through LocalOptions.Marks.
type Marks struct {
	mu      sync.Mutex
	at      map[string]time.Time
	removed map[string]time.Time
	fixed   map[string]fixMark
}

// NewMarks returns empty marks.
func NewMarks() *Marks { return &Marks{} }

type fixMark struct {
	job string
	at  time.Time
}

// MarkFixed records that agent's fix job finished at at.
func (m *Marks) MarkFixed(agent, job string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fixed == nil {
		m.fixed = map[string]fixMark{}
	}
	m.fixed[agent] = fixMark{job: job, at: at}
}

// FixedSince is the job of agent's last fix when it finished after since.
func (m *Marks) FixedSince(agent string, since time.Time) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.fixed[agent]
	if !ok || !f.at.After(since) {
		return ""
	}
	return f.job
}

// MarkUpdated records that agent's UPDATE finished at at.
func (m *Marks) MarkUpdated(agent string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.at == nil {
		m.at = map[string]time.Time{}
	}
	m.at[agent] = at
}

// UpdatedSince is whether agent's last UPDATE finished after since.
func (m *Marks) UpdatedSince(agent string, since time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.at[agent]
	return ok && at.After(since)
}

func (m *Marks) markRemoved(agents []string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removed == nil {
		m.removed = map[string]time.Time{}
	}
	for _, a := range agents {
		m.removed[a] = at
	}
}

func (m *Marks) removedSince(agent string, since time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.removed[agent]
	return ok && at.After(since)
}

func (s *LocalService) markFixed(agent, job string) {
	s.updated.MarkFixed(agent, job, s.opts.Now())
}

func (s *LocalService) fixedSince(agent string, since time.Time) string {
	return s.updated.FixedSince(agent, since)
}

func (s *LocalService) markRemoved(agents []string) {
	s.updated.markRemoved(agents, s.opts.Now())
}

func (s *LocalService) removedSince(agent string, since time.Time) bool {
	return s.updated.removedSince(agent, since)
}

func (s *LocalService) markUpdated(agent string) {
	s.updated.MarkUpdated(agent, s.opts.Now())
}

func (s *LocalService) updatedSince(agent string, since time.Time) bool {
	return s.updated.UpdatedSince(agent, since)
}
