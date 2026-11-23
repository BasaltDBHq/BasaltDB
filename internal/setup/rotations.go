package setup

import (
	"errors"
	"io/fs"
	"os"
	"sync"
)

// Rotations hands the setup page's REPAIR a running agent's password: the
// page writes the new credential, and the agent's pool logs in with it from
// its next connection, without a restart.
type Rotations struct {
	mu   sync.Mutex
	sets map[string]func(password string)
}

// NewRotations returns rotations with no agent.
func NewRotations() *Rotations { return &Rotations{sets: map[string]func(string){}} }

// Add makes set the way agent's password is replaced.
func (r *Rotations) Add(agent string, set func(password string)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sets[agent] = set
}

// Changed replaces agent's password, when the agent runs here.
func (r *Rotations) Changed(agent, password string) {
	r.mu.Lock()
	set := r.sets[agent]
	r.mu.Unlock()
	if set != nil {
		set(password)
	}
}

// ConfigGone reports whether the config at path is gone: the setup page's
// REMOVE deleted it with the engine's last agent.
func ConfigGone(path string) func() bool {
	return func() bool {
		_, err := os.Lstat(path)
		return errors.Is(err, fs.ErrNotExist)
	}
}
