package app

import (
	"log/slog"
	"os"
	"os/exec"
	"slices"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/out/binwatch"
)

// binaryWatch is engine.BinaryWatch on this machine's binaries.
type binaryWatch struct{}

// ExecPath is the path this process was started from as arg0 names it,
// looked up on PATH, and checked to be the running binary exe.
func (binaryWatch) ExecPath(arg0, exe string) (string, error) {
	return binwatch.ExecPath(arg0, exec.LookPath, func() (string, error) { return exe, nil }, binwatch.OS{}.Stat)
}

// osRestart watches the binary this engine was started from. When it
// cannot (its path cannot be read), the engine runs without the restart.
func osRestart(log *slog.Logger) engine.BinaryRestart {
	sys := binwatch.OS{}
	exe, err := os.Executable()
	if err != nil {
		log.Warn("the engine does not restart onto an upgraded binary: its own path is unknown", "err", err)
		return engine.BinaryRestart{}
	}
	path, err := binwatch.ExecPath(os.Args[0], exec.LookPath, func() (string, error) { return exe, nil }, sys.Stat)
	if err != nil {
		log.Warn("the engine does not restart onto an upgraded binary: its own path is unknown", "err", err)
		return engine.BinaryRestart{}
	}
	w, err := binwatch.New(path, exe, sys, os.Geteuid() == 0, log)
	if err != nil {
		log.Warn("the engine does not restart onto an upgraded binary: its binary cannot be watched", "path", path, "err", err)
		return engine.BinaryRestart{}
	}
	path = w.Path()
	log.Info("the engine restarts onto an upgraded binary installed at its path", "path", path)
	argv := slices.Clone(os.Args)
	return engine.BinaryRestart{Upgrade: w.Wait, Exec: func() error {
		if err := w.Recheck(); err != nil {
			return err
		}
		return binwatch.Exec(path, argv, os.Environ())
	}}
}
