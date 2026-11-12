package service

import (
	"context"
	"io"
	"os"
	"os/exec"
	"os/user"
)

// OSSystem runs install steps on this machine. Commands inherit stdout and
// stderr so a person sees what the service manager says.
type OSSystem struct {
	Stdout, Stderr io.Writer
}

// UserExists reports whether the OS user exists.
func (OSSystem) UserExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

// Output runs a command and returns its stdout.
func (OSSystem) Output(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	return string(out), err
}

// Run runs a command.
func (s OSSystem) Run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = s.Stdout, s.Stderr
	return cmd.Run()
}

// WriteFile writes a file with mode, also when it already exists with
// another mode.
func (OSSystem) Remove(path string) error {
	return os.Remove(path)
}

// Exists reports whether a file exists.
func (OSSystem) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
