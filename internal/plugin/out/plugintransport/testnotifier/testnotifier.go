// Package testnotifier builds and drives a notifier plugin for the engine's
// tests: a real plugin, built from the SDK, that serves feed.observe and
// approval.deliver and misbehaves on request. It is test support: production
// code never imports it, and it imports nothing of the engine.
//
// Build it once, in TestMain, then write a plugin directory per test:
//
//	bin, err := testnotifier.Build(dir) // go build of the command below
//	...
//	err = testnotifier.WriteDir(pluginDir, bin, testnotifier.Options{
//		Record:  filepath.Join(tmp, "received.jsonl"),
//		Control: filepath.Join(tmp, "mode"),
//	})
//
// pluginDir then holds bin/basalt-test-notifier and an unsigned
// basalt-plugin.json naming both hooks. Sign it (plugin.SignManifest, writing basalt-plugin.json.sig) for an entry
// that needs a trusted signature, or install it through the approval flow,
// which accepts it unsigned. Then:
//
//   - ReadRecords(Record) returns every hook call the plugin received, in
//     order, with the agent and the exact events or notice. A call is
//     recorded before the plugin acts on it, so a hang or a crash still
//     shows the call arrived.
//   - SetMode(Control, m) switches how the next hook calls are answered,
//     while it runs. ModeBadSeq and ModeBadJSON are the exception: they speak
//     the protocol without the SDK (the SDK refuses to send such answers), so
//     the process picks them only when it starts. Set the mode, then make
//     the engine start the plugin again (ModeCrash on a call does it).
//
// The engine starts a plugin with no environment but the socket variable, so
// the settings travel in the manifest's "args". A test that starts the
// binary itself may set them in the environment instead (EnvMode, EnvRecord,
// EnvControl, EnvDelay, EnvHooks); a flag wins over the environment.
package testnotifier

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Package is the command's import path, for go build.
const Package = "github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/testnotifier/cmd/basalt-test-notifier"

// The plugin's identity, as its manifest and its initialize answer say.
const (
	Name    = "test-notifier"
	Version = "1.0.0"
	Binary  = "basalt-test-notifier"
)

// The hooks it can serve.
const (
	HookFeedObserve     = "feed.observe"
	HookApprovalDeliver = "approval.deliver"
)

// Mode is how the plugin answers hook calls. initialize, health (except in
// ModeNotReady) and shutdown are always answered normally.
type Mode string

// The modes.
const (
	// ModeOK answers feed.observe with the batch's last seq and
	// approval.deliver with {}.
	ModeOK Mode = "ok"
	// ModeLate waits for the delay (default 5s), ignoring the call's
	// deadline, and then answers. Through the SDK a reply after the deadline
	// is a deadline-exceeded error, so the engine sees TIMEOUT, as for
	// ModeHang; unlike ModeHang, the plugin frees the call's slot after the
	// delay, and a delay shorter than the deadline answers as ModeOK.
	ModeLate Mode = "late"
	// ModeHang never answers.
	ModeHang Mode = "hang"
	// ModeCrash exits with code 3 on the call, without answering.
	ModeCrash Mode = "crash"
	// ModeNotReady answers health NOT_READY, and hook calls as ModeOK.
	ModeNotReady Mode = "not-ready"
	// ModeBadSeq answers feed.observe with a lastSeq one past the batch's
	// last, which is no seq of the batch; approval.deliver as ModeOK.
	// JSON-RPC transports only; picked at start.
	ModeBadSeq Mode = "bad-seq"
	// ModeBadJSON answers every hook call with a line that is not JSON.
	// JSON-RPC transports only; picked at start.
	ModeBadJSON Mode = "bad-json"
)

// CrashExit is the exit code of ModeCrash.
const CrashExit = 3

// DefaultDelay is ModeLate's delay when Options.Delay is not set.
const DefaultDelay = 5 * time.Second

// File modes, and the longest record line ReadRecords reads.
const (
	dirMode        = 0o755
	binaryMode     = 0o755
	privateMode    = 0o600
	maxRecordBytes = 8 << 20
)

// The environment a test that starts the binary itself may set.
const (
	EnvMode    = "BASALT_TEST_NOTIFIER_MODE"
	EnvRecord  = "BASALT_TEST_NOTIFIER_RECORD"
	EnvControl = "BASALT_TEST_NOTIFIER_CONTROL"
	EnvDelay   = "BASALT_TEST_NOTIFIER_DELAY"
	EnvHooks   = "BASALT_TEST_NOTIFIER_HOOKS"
)

// Options are the plugin's settings, written into the manifest's args.
type Options struct {
	// Mode at start; ModeOK when empty. A non-empty Control file wins.
	Mode Mode
	// Record is the absolute path of the file every hook call is appended
	// to, one JSON line each. Never inside the plugin's own directory: the
	// engine refuses an installed copy that changed.
	Record string
	// Control is the absolute path of a file holding a mode, read at start
	// and at every hook call. A missing or empty file means Mode.
	Control string
	// Delay is ModeLate's delay.
	Delay time.Duration
	// Hooks are the hooks it declares, both when empty.
	Hooks []string
	// Transport is the manifest's endpoint transport: jsonrpc-stdio (the
	// default), jsonrpc-unix or connectrpc.
	Transport string
}

// Args are the command-line arguments that carry the options.
func (o Options) Args() []string {
	var a []string
	if o.Mode != "" {
		a = append(a, "-mode", string(o.Mode))
	}
	if o.Record != "" {
		a = append(a, "-record", o.Record)
	}
	if o.Control != "" {
		a = append(a, "-control", o.Control)
	}
	if o.Delay > 0 {
		a = append(a, "-delay", o.Delay.String())
	}
	if len(o.Hooks) > 0 {
		a = append(a, "-hooks", strings.Join(o.Hooks, ","))
	}
	if o.Transport != "" {
		a = append(a, "-transport", o.Transport)
	}
	return a
}

func (o Options) hooks() []string {
	if len(o.Hooks) == 0 {
		return []string{HookFeedObserve, HookApprovalDeliver}
	}
	return o.Hooks
}

// Build compiles the plugin into dir and returns the binary's path. Call it
// once per test binary, from TestMain.
func Build(dir string) (string, error) {
	out := filepath.Join(dir, Binary)
	cmd := exec.Command("go", "build", "-o", out, Package)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("testnotifier: go build: %w: %s", err, b)
	}
	return out, nil
}

// Manifest is the plugin's basalt-plugin.json for these options and the
// binary's SHA-256.
func Manifest(o Options, sum [sha256.Size]byte) ([]byte, error) {
	transport := o.Transport
	if transport == "" {
		transport = "jsonrpc-stdio"
	}
	hooks := map[string]map[string]string{}
	for _, h := range o.hooks() {
		switch h {
		case HookFeedObserve:
			hooks[h] = map[string]string{"contract": "feed/1"}
		case HookApprovalDeliver:
			hooks[h] = map[string]string{"contract": "deliver/1"}
		default:
			return nil, fmt.Errorf("testnotifier: %q is not a notifier hook", h)
		}
	}
	args := o.Args()
	if args == nil {
		args = []string{}
	}
	return json.MarshalIndent(map[string]any{
		"manifestVersion": 1, "name": Name, "version": Version, "publisher": "Basalt tests",
		"protocol": []string{"basalt-plugin/1"},
		"hooks":    hooks,
		"endpoint": map[string]any{"local": map[string]any{"transport": transport, "command": "bin/" + Binary, "args": args}},
		"files":    map[string]string{"bin/" + Binary: fmt.Sprintf("sha256:%x", sum)},
		"network":  map[string]any{"egress": []string{}},
	}, "", "  ")
}

// WriteDir makes dir a plugin directory: bin/basalt-test-notifier (a copy of
// bin, mode 0755) and an unsigned basalt-plugin.json for o.
func WriteDir(dir, bin string, o Options) error {
	if err := os.MkdirAll(filepath.Join(dir, "bin"), dirMode); err != nil {
		return err
	}
	in, err := os.Open(bin)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(filepath.Join(dir, "bin", Binary), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, binaryMode)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	m, err := Manifest(o, sum)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "basalt-plugin.json"), m, privateMode)
}

// SetMode writes m to the control file, by rename, so the plugin never reads
// half of it.
func SetMode(control string, m Mode) error {
	tmp := control + ".tmp"
	if err := os.WriteFile(tmp, []byte(m), privateMode); err != nil {
		return err
	}
	return os.Rename(tmp, control)
}

// Record is one hook call the plugin received.
type Record struct {
	// Hook is feed.observe or approval.deliver.
	Hook  string `json:"hook"`
	Agent string `json:"agent"`
	// Mode is the mode the call was answered in.
	Mode Mode `json:"mode"`
	// Events are a feed.observe call's events, each its exact JSON bytes.
	Events []json.RawMessage `json:"events,omitempty"`
	// Event is an approval.deliver call's notice, its exact JSON bytes.
	Event json.RawMessage `json:"event,omitempty"`
}

// ReadRecords reads every call recorded so far. A missing file is no calls.
func ReadRecords(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Record
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), maxRecordBytes)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("testnotifier: record line: %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
