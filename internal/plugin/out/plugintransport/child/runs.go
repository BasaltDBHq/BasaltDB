package child

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/lib/atomicfile"
)

// Runs is the directory where the engine records each local plugin process
// it starts, so its next start can stop one an engine crash left running and
// remove its socket directory (Reap). Each record also names the engine that
// wrote it, so an engine sharing the directory with another that still runs
// never reaps that engine's plugins.
type Runs struct {
	// Dir is the records' directory, made 0700 when the first record is
	// written.
	Dir string
}

// runsDirMode: the engine's user only.
const runsDirMode = 0o700

// recordSuffix names a record file: <pid>.json.
const recordSuffix = ".json"

// maxRecordBytes bounds a record read back; a real one is far smaller.
const maxRecordBytes = 4 << 10

// socketName is the one file a socket directory holds (dial's p.sock).
const socketName = "p.sock"

// record is what the engine knows of a plugin process it started: its pid
// (the leader of its own process group), the start-time identity of that
// pid when it started (procStart), and the socket directory made for it,
// if any.
type record struct {
	PID       int    `json:"pid"`
	Start     string `json:"start"`
	SocketDir string `json:"socketDir,omitempty"`
	// EnginePID and EngineStart are the engine that started it.
	EnginePID   int    `json:"enginePid"`
	EngineStart string `json:"engineStart"`
}

// ErrNotRecorded: a process was started but its run record could not be
// written, so it was stopped again.
var ErrNotRecorded = errors.New("the plugin process could not be recorded in the engine's state directory, so it was stopped")

// recordStart records the process pid just started, with its start-time
// identity and its socket directory.
func recordStart(r *Runs, pid int, socketDir string) (string, error) {
	start, err := procStart(pid)
	if err != nil {
		return "", fmt.Errorf("%w (its start time cannot be read)", ErrNotRecorded)
	}
	engineStart, err := procStart(os.Getpid())
	if err != nil {
		return "", fmt.Errorf("%w (the engine's start time cannot be read)", ErrNotRecorded)
	}
	path, err := r.write(record{PID: pid, Start: start, SocketDir: socketDir, EnginePID: os.Getpid(), EngineStart: engineStart})
	if err != nil {
		return "", ErrNotRecorded
	}
	return path, nil
}

// write records a started process. The file is written whole (a temporary
// file renamed into place), so a crash leaves no half record.
func (r *Runs) write(rec record) (string, error) {
	if err := os.Mkdir(r.Dir, runsDirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	fi, err := os.Lstat(r.Dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() || !ownedByMe(fi) {
		return "", errors.New("the plugin run directory is not a directory of the engine's user")
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	path := filepath.Join(r.Dir, strconv.Itoa(rec.PID)+recordSuffix)
	if err := atomicfile.Write(path, b, atomicfile.Options{Mode: recordFileMode}); err != nil {
		return "", err
	}
	return path, nil
}

// Reap stops the plugin processes an earlier engine recorded in dir and did
// not stop (it was killed), and removes their socket directories, then
// drops every record. The engine calls it at start, holding its lock and
// before it starts any plugin. It acts only on what it can prove:
//
//   - a process group is killed only when its leader is alive and has the
//     start time recorded for it, so a pid the OS gave to another process
//     since is never touched; pid 0, 1 and the engine's own are ignored;
//   - a socket directory is removed only when it is a directory (not a
//     symlink) of the engine's user holding nothing but its socket: the
//     socket is unlinked and the empty directory removed, nothing else.
//
// A record that cannot be read or parsed is dropped without acting on it. A
// missing dir is nothing to reap.
func Reap(dir string, log *slog.Logger) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil || !fi.IsDir() || !ownedByMe(fi) {
		log.Warn("plugin run records not read: the directory is not the engine's own", "dir", dir)
		return
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		log.Warn("plugin run records not read", "dir", dir, "err", err)
		return
	}
	for _, de := range des {
		path := filepath.Join(dir, de.Name())
		if strings.HasSuffix(de.Name(), recordSuffix) && de.Type().IsRegular() {
			rec, err := readRecord(path)
			switch {
			case err != nil:
				log.Warn("plugin run record dropped: it cannot be read", "file", de.Name())
			case engineRuns(rec):
				continue // another engine's plugin, still in use: kept
			default:
				reapOne(rec, log)
			}
		}
		if de.Type().IsRegular() {
			_ = os.Remove(path) // a record, or a temporary file a crash left
		}
	}
}

func readRecord(path string) (record, error) {
	var rec record
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return rec, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil {
		return rec, err
	}
	if len(b) > maxRecordBytes {
		return rec, errors.New("record too large")
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, err
	}
	if rec.Start == "" || rec.EngineStart == "" {
		return rec, errors.New("record has no start time")
	}
	// Only a pid the kernel takes as pid_t as given: a larger one would be
	// truncated there, and 4294967295 would become -1, every process.
	if rec.PID < 2 || rec.PID > math.MaxInt32 || rec.EnginePID < 2 || rec.EnginePID > math.MaxInt32 {
		return rec, errors.New("record has a pid out of range")
	}
	return rec, nil
}

// engineRuns reports whether the engine that wrote rec still runs, and is
// not this one.
func engineRuns(rec record) bool {
	if rec.EnginePID == os.Getpid() {
		return false
	}
	start, err := reapStart(rec.EnginePID)
	return err == nil && start == rec.EngineStart
}

// The process lookups Reap uses; tests replace them.
var (
	reapStart = procStart
	reapKill  = killGroupID
)

func reapOne(rec record, log *slog.Logger) {
	if rec.PID > 1 && rec.PID != os.Getpid() && rec.PID != getpgrp() {
		if start, err := reapStart(rec.PID); err == nil && start == rec.Start {
			if err := reapKill(rec.PID); err == nil {
				log.Warn("stopped a plugin process an earlier engine left running", "pid", rec.PID)
			}
		}
	}
	if rec.SocketDir != "" {
		if err := removeSocketDir(rec.SocketDir); err != nil {
			log.Warn("socket directory of an earlier plugin process kept", "dir", rec.SocketDir, "why", err.Error())
		}
	}
}

// removeSocketDir removes dir when it is a directory of the engine's user
// holding at most its socket. A directory already gone is no error.
func removeSocketDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("not an absolute path")
	}
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() || !ownedByMe(fi) {
		return errors.New("not a directory of the engine's user")
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		if de.Name() != socketName || de.Type()&fs.ModeSocket == 0 {
			return fmt.Errorf("it holds more than its socket")
		}
	}
	if len(des) == 1 {
		if err := os.Remove(filepath.Join(dir, socketName)); err != nil {
			return err
		}
	}
	return os.Remove(dir)
}

// recordFileMode keeps a run record to the engine's own user.
const recordFileMode = 0o600
