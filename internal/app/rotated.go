package app

import "sync"

// rotations hands the setup page's REPAIR a running agent's password: the
// page writes the new credential, and the agent's pool logs in with it from
// its next connection, without a restart.
type rotations struct {
	mu   sync.Mutex
	sets map[string]func(password string)
}

func newRotations() *rotations { return &rotations{sets: map[string]func(string){}} }

// add makes set the way agent's password is replaced.
func (r *rotations) add(agent string, set func(password string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets[agent] = set
}

// changed replaces agent's password, when the agent runs here.
func (r *rotations) changed(agent, password string) {
	r.mu.Lock()
	set := r.sets[agent]
	r.mu.Unlock()
	if set != nil {
		set(password)
	}
}
