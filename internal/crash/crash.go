// Package crash saves a local, scrubbed report when basalt panics, lists and
// shows the saved reports, and builds the GitHub issue link for one. Nothing
// here sends anything: the person opens the link and submits the issue
// themselves (CONTRACT.md, Crash reports).
package crash

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/pkg/uniqueid"
)

// Kinds of crash.
const (
	KindPanic = "PANIC"
	KindFatal = "FATAL"
)

const (
	// Keep is how many reports a directory holds: saving one past it
	// deletes the oldest.
	Keep = 20
	// DirName is the directory, under the state directory, that holds them.
	DirName = "crash"

	dirMode  = 0o700
	fileMode = 0o600
	// sharedDirMode and sharedFileMode let the person read the reports of
	// an engine that runs as another OS user; they hold only scrubbed text.
	sharedDirMode  = 0o755
	sharedFileMode = 0o644
	// maxStack bounds the saved stack, in bytes.
	maxStack = 16 << 10
	// maxMessage bounds the saved panic message, in bytes.
	maxMessage = 200
)

// Report is one saved crash. Its JSON is exactly what `basalt crash show`
// prints and what the issue body is built from.
type Report struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Version   string    `json:"version"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	GoVersion string    `json:"goVersion"`
	// Command is the basalt command or MCP tool that was running.
	Command string `json:"command"`
	Kind    string `json:"kind"`
	// ErrorCode is the error code the crash became, such as INTERNAL.
	ErrorCode string `json:"errorCode,omitempty"`
	// Message is the panic's message for a runtime error; any other panic
	// value is reported by its type only.
	Message string `json:"message,omitempty"`
	Stack   string `json:"stack"`
}

// Input is what a crash handler knows.
type Input struct {
	// Command is the command or tool name; anything not shaped like one is
	// saved as "unknown".
	Command   string
	Kind      string
	ErrorCode string
	// Value is the recovered panic value.
	Value any
	// Stack is runtime/debug.Stack from the deferred handler.
	Stack []byte
}

// Recorder saves reports into Dir.
type Recorder struct {
	Dir     string
	Version string
	Scrub   *Scrubber
	Now     func() time.Time
	// Shared makes the directory and files readable by every user, for the
	// engine service, whose state directory belongs to its own OS user.
	Shared bool
}

var (
	reCommand = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,39}$`)
	reCode    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// unknown is the command of a crash whose command name has no allowed shape.
const unknown = "unknown"

// Build makes the scrubbed report for in. It never keeps a panic value's
// text unless the value is a Go runtime error (an index out of range, a nil
// dereference), whose message the runtime writes and no one else.
func (r Recorder) Build(in Input) Report {
	rep := Report{
		ID: uniqueid.New(), Time: r.Now().UTC(), Version: r.Version,
		OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(),
		Command: unknown, Kind: in.Kind,
	}
	if reCommand.MatchString(in.Command) {
		rep.Command = in.Command
	}
	if rep.Kind != KindFatal {
		rep.Kind = KindPanic
	}
	if reCode.MatchString(in.ErrorCode) {
		rep.ErrorCode = in.ErrorCode
	}
	rep.Message = r.message(in.Value)
	rep.Stack = clip(r.Scrub.Stack(string(in.Stack)), maxStack)
	return rep
}

// message is the report's description of a panic value.
func (r Recorder) message(v any) string {
	if v == nil {
		return ""
	}
	rtErr, ok := v.(runtime.Error)
	if !ok {
		return "panic value of type " + typeName(v)
	}
	return clip(r.Scrub.Text(rtErr.Error()), maxMessage)
}

func typeName(v any) string {
	return fmt.Sprintf("%T", v)
}

// clip cuts s to n bytes on a line boundary when it has one.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	if i := strings.LastIndex(s, "\n"); i > 0 {
		s = s[:i]
	}
	return strings.ToValidUTF8(s, "") + "\n...trimmed..."
}

// Save builds the report for in, writes it to Dir and keeps the newest Keep.
func (r Recorder) Save(in Input) (Report, error) {
	rep := r.Build(in)
	dm, fm := os.FileMode(dirMode), os.FileMode(fileMode)
	if r.Shared {
		dm, fm = sharedDirMode, sharedFileMode
	}
	if err := os.MkdirAll(r.Dir, dm); err != nil {
		return rep, err
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return rep, err
	}
	if err := os.WriteFile(filepath.Join(r.Dir, rep.ID+".json"), append(raw, '\n'), fm); err != nil {
		return rep, err
	}
	return rep, prune(r.Dir)
}

// prune deletes the oldest reports in dir past Keep. The ids are UUIDv7, so
// name order is time order.
func prune(dir string) error {
	names, err := reportFiles(dir)
	if err != nil || len(names) <= Keep {
		return err
	}
	var errs []error
	for _, n := range names[:len(names)-Keep] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// reportFiles lists dir's report files, oldest first. A missing directory
// has none.
func reportFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// List returns the reports in dirs, newest first. A directory that cannot
// be read (the engine's state directory belongs to another user) is skipped.
// A file that is not a report is skipped.
func List(dirs ...string) []Report {
	var out []Report
	seen := map[string]bool{}
	for _, d := range dirs {
		names, _ := reportFiles(d)
		for _, n := range names {
			rep, err := load(filepath.Join(d, n))
			if err != nil || seen[rep.ID] {
				continue
			}
			seen[rep.ID] = true
			out = append(out, rep)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// maxReportFile bounds how much of a file is read as a report.
const maxReportFile = 256 << 10

func load(p string) (Report, error) {
	f, err := os.Open(p)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	var rep Report
	dec := json.NewDecoder(&limitedReader{f: f, left: maxReportFile})
	if err := dec.Decode(&rep); err != nil {
		return Report{}, err
	}
	if rep.ID == "" || strings.TrimSuffix(filepath.Base(p), ".json") != rep.ID {
		return Report{}, errors.New("not a crash report")
	}
	return rep, nil
}

type limitedReader struct {
	f    *os.File
	left int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errors.New("report too large")
	}
	if len(p) > l.left {
		p = p[:l.left]
	}
	n, err := l.f.Read(p)
	l.left -= n
	return n, err
}

// ErrNotFound is what Find returns for an id that matches no report.
var ErrNotFound = errors.New("no crash report has that id (basalt crash list shows them)")

// Find returns the report whose id is id. (Ids are UUIDv7, whose leading
// characters are the time, so a prefix would rarely be unique.)
func Find(id string, dirs ...string) (Report, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, rep := range List(dirs...) {
		if rep.ID == id {
			return rep, nil
		}
	}
	return Report{}, ErrNotFound
}

// Show is the text `basalt crash show` prints: exactly the report's JSON,
// which is all that `basalt crash report` puts in the issue.
func (rep Report) Show() string {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return "the report cannot be printed: " + err.Error() + "\n"
	}
	return string(raw) + "\n"
}
