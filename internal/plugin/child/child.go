// Package child starts a local plugin's process the one way the engine and
// basalt plugin check start it: in its own process group, in the plugin's
// installed copy, with only the environment it is given. Stopping it kills
// the whole group, so nothing the plugin started outlives it.
package child

import (
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"
)

// Timing of a stop.
const (
	// reapWait bounds the wait for a killed group's leader to be reaped.
	reapWait = time.Second
	// waitDelay bounds how long reaping waits for a stderr copy to finish
	// when a process the plugin started still holds the pipe.
	waitDelay = time.Second
)

// Spec is what a child process gets.
type Spec struct {
	// Path is the command, an absolute path.
	Path string
	Args []string
	// Dir is the working directory: the plugin's installed copy. Required,
	// so the child never inherits the engine's.
	Dir string
	// Env is the child's whole environment; nil means an empty one.
	Env []string
	// Stdin, Stdout and Stderr are as for exec.Cmd; nil discards.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Process is a started child.
type Process struct {
	cmd    *exec.Cmd
	exited chan struct{}
	once   sync.Once
}

// ErrNoDir: a spec without a working directory.
var ErrNoDir = errors.New("child: a plugin process needs its working directory")

// Start starts s. The child is the leader of a new process group.
func Start(s Spec) (*Process, error) {
	if s.Dir == "" {
		return nil, ErrNoDir
	}
	cmd := exec.Command(s.Path, s.Args...)
	cmd.Dir = s.Dir
	cmd.Env = append([]string{}, s.Env...)
	cmd.Stdin, cmd.Stdout = s.Stdin, s.Stdout
	if s.Stderr != nil {
		cmd.Stderr = s.Stderr
	}
	cmd.WaitDelay = waitDelay
	setGroup(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &Process{cmd: cmd, exited: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.exited) }()
	return p, nil
}

// Exited is closed once the child has exited and been reaped.
func (p *Process) Exited() <-chan struct{} { return p.exited }

// Stop kills the child's whole process group, also when the child itself
// has already exited, and waits a moment for the child to be reaped. Safe
// to call more than once.
func (p *Process) Stop() {
	p.once.Do(func() {
		killGroup(p.cmd)
		select {
		case <-p.exited:
		case <-time.After(reapWait):
		}
	})
}
