package localsetup

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/config"
)

// Not your database (CONTRACT.md, Not your database): the page asks the
// person whose database the engine serves. The engine answers it from its
// own files and changes nothing. No route resets anything: a "No" only
// leaves a mark that basalt init, polling, reads once, and basalt init
// then asks the person for the administrator password in the system's
// dialog, whose fixed script resets the engine. Host and Origin can be
// forged on loopback, so the mark is worth only that dialog: a program
// that forges it gets a password prompt the person can close.

// CodeResetAsked is the answer to basalt init's probe (a check with an
// empty body) once the person answered "No, this isn't mine": init then
// runs the reset through the administrator dialog. It is answered once.
const CodeResetAsked = "RESET_ASKED"

// resetAskedFor is how long a "No" waits for basalt init to read it.
const resetAskedFor = 5 * time.Minute

// EngineAnswer is what the engine is set up with: its agents and the
// databases their credential files name, read from the files, never from
// a login and never with a password.
type EngineAnswer struct {
	Agents    []string         `json:"agents"`
	Databases []EngineDatabase `json:"databases"`
}

// EngineDatabase is a database an agent's credential file names.
type EngineDatabase struct {
	Database string `json:"database"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

// resetMark is the person's "No", until basalt init reads it.
type resetMark struct {
	mu sync.Mutex
	at time.Time
}

// Engine answers what the engine is set up with. It names no agent: the
// setup it asks about may have been made under an agent name and OS user
// the person's link does not carry.
func (s *Service) Engine(_ context.Context) (EngineAnswer, error) {
	cfg, err := s.engineConfig()
	if err != nil {
		return EngineAnswer{}, err
	}
	out := EngineAnswer{Agents: []string{}, Databases: []EngineDatabase{}}
	for _, a := range cfg.Agents {
		out.Agents = append(out.Agents, a.Name)
		h, err := s.hostOf(a)
		if err != nil {
			continue
		}
		if d := (EngineDatabase{Database: h.database, Host: h.host, Port: h.port}); !slices.Contains(out.Databases, d) {
			out.Databases = append(out.Databases, d)
		}
	}
	return out, nil
}

// NotMine marks the person's "No, this isn't mine" for basalt init. It
// changes no file and no database.
func (s *Service) NotMine(_ context.Context) error {
	if _, err := s.engineConfig(); err != nil {
		return err
	}
	s.mark.mu.Lock()
	s.mark.at = s.opts.Now()
	s.mark.mu.Unlock()
	return nil
}

// resetAsked reads the mark once: true when the person answered "No"
// within resetAskedFor.
func (s *Service) resetAsked() bool {
	s.mark.mu.Lock()
	defer s.mark.mu.Unlock()
	at := s.mark.at
	s.mark.at = time.Time{}
	return !at.IsZero() && s.opts.Now().Sub(at) < resetAskedFor
}

// engineConfig is the config of a person-operated engine that serves the
// setup page's jobs, or the refusal every such request gets.
func (s *Service) engineConfig() (config.Config, error) {
	if !s.opts.Configured {
		return config.Config{}, refuse(CodeJobUnavailable, "This engine has no config yet. Ask the agent for a new link.")
	}
	if err := s.engineRemoved(); err != nil {
		return config.Config{}, err
	}
	if s.opts.Euid() == 0 {
		return config.Config{}, refuse(CodeJobUnavailable, "An engine running as root never serves this page's jobs.")
	}
	cfg, err := s.be.LoadConfig(s.opts.ConfigPath)
	if err != nil {
		return config.Config{}, refuse(CodeSetupFailed, "This engine cannot read its config; nothing changed.")
	}
	if cfg.AgentOperated() {
		return config.Config{}, refuse(CodeJobUnavailable, "This engine is operated by its agent: it is set up from the connect page, not here.")
	}
	return cfg, nil
}
