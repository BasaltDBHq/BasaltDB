package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	protocol "github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
)

// fake is a Transport that answers initialize from the manifest and runs
// onCall for every other method.
type fake struct {
	mu       sync.Mutex
	calls    []string
	initResp *protocol.InitializeResponse
	initReq  protocol.InitializeRequest
	onCall   func(ctx context.Context, method string) error
	// answer, when set, answers a hook call with its params and result.
	answer func(method string, params, result any) error
	closed atomic.Bool
}

func (f *fake) Call(ctx context.Context, method string, params, result any) error {
	f.mu.Lock()
	f.calls = append(f.calls, method)
	f.mu.Unlock()
	if method == protocol.MethodInitialize {
		f.initReq, _ = params.(protocol.InitializeRequest)
		out, _ := result.(*protocol.InitializeResponse)
		*out = *f.initResp
		return nil
	}
	if f.onCall != nil {
		return f.onCall(ctx, method)
	}
	if f.answer != nil {
		return f.answer(method, params, result)
	}
	return nil
}

func (f *fake) Close() error { f.closed.Store(true); return nil }

func (f *fake) methods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func manifest(name string) Manifest {
	return Manifest{
		ManifestVersion: 1, Name: name, Version: "1.0.0", Publisher: "t",
		Protocol: []string{protocol.Version1},
		Hooks: map[string]protocol.HookDecl{
			string(HookWireDetect): {Contract: "detector/1", Roles: []string{"VALUE"}, EntityTypes: []string{"EMAIL", "PHONE"}},
		},
		Endpoint: Endpoint{Local: &LocalEndpoint{Transport: "jsonrpc-stdio", Command: "p"}},
	}
}

func entry(name, instance string, agents ...string) Entry {
	return Entry{Key: EntryKey{name, instance}, Manifest: manifest(name), Agents: agents, Timeout: 100 * time.Millisecond}
}

func goodInit(m Manifest) *protocol.InitializeResponse {
	hooks := map[string]protocol.HookDecl{}
	for h, d := range m.Hooks {
		hooks[h] = d
	}
	return &protocol.InitializeResponse{Protocol: protocol.Version1, Name: m.Name, Version: m.Version, Hooks: hooks}
}

func register(t *testing.T, h *Host, e Entry) *fake {
	t.Helper()
	f := &fake{initResp: goodInit(e.Manifest)}
	if err := h.Register(context.Background(), e, f); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return f
}

func TestCallRefusesUnlistedAgent(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "product-a")
	f := register(t, h, e)
	before := len(f.methods())

	err := h.Call(context.Background(), e.Key, []string{"product-a", "client-x"}, "detect", nil, nil)
	if !errors.Is(err, ErrAgentNotListed) {
		t.Fatalf("err = %v, want ErrAgentNotListed", err)
	}
	if strings.Contains(err.Error(), "client-x") || strings.Contains(err.Error(), "product-a") {
		t.Fatalf("error names an agent: %v", err)
	}
	if got := len(f.methods()); got != before {
		t.Fatalf("transport saw %d calls after the refused call", got-before)
	}
	if err := h.Call(context.Background(), e.Key, nil, "detect", nil, nil); !errors.Is(err, ErrAgentNotListed) {
		t.Fatalf("no agents: err = %v", err)
	}
	if err := h.Call(context.Background(), e.Key, []string{"product-a"}, "detect", nil, nil); err != nil {
		t.Fatalf("listed agent: %v", err)
	}
}

func TestCallRefusesLifecycleMethods(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "product-a")
	f := register(t, h, e)
	before := len(f.methods())
	for _, m := range []string{protocol.MethodInitialize, protocol.MethodHealth, protocol.MethodShutdown} {
		err := h.Call(context.Background(), e.Key, []string{"product-a"}, m, nil, nil)
		if err == nil {
			t.Fatalf("Call sent %q", m)
		}
		if strings.Contains(err.Error(), "product-a") {
			t.Fatalf("error names an agent: %v", err)
		}
	}
	if got := len(f.methods()); got != before {
		t.Fatalf("transport saw %d calls after the refused calls", got-before)
	}
}

func TestDeadlineEnforced(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	f := register(t, h, e)
	f.onCall = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	err := h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil)
	assertClass(t, err, ClassTimeout)
}

func TestFifthCallWaitsThenTimesOut(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	e.Timeout = 200 * time.Millisecond
	f := register(t, h, e)
	release := make(chan struct{}) // never closed: every call runs to its deadline
	var inflight, peak atomic.Int32
	f.onCall = func(ctx context.Context, _ string) error {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		defer inflight.Add(-1)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil)
		}()
		time.Sleep(5 * time.Millisecond)
	}
	wg.Wait()
	close(errs)
	if peak.Load() > protocol.MaxInFlight {
		t.Fatalf("peak in flight = %d, want <= %d", peak.Load(), protocol.MaxInFlight)
	}
	var timeouts int
	for err := range errs {
		var ce *CallError
		if errors.As(err, &ce) && ce.Class == ClassTimeout {
			timeouts++
		}
	}
	if timeouts != 5 {
		// Every call blocks until its deadline, so all five end in TIMEOUT:
		// four in the transport, the fifth while waiting for a slot.
		t.Fatalf("timeouts = %d, want 5", timeouts)
	}
}

func TestFifthCallProceedsWhenSlotFrees(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	e.Timeout = 2 * time.Second
	f := register(t, h, e)
	release := make(chan struct{})
	var started atomic.Int32
	f.onCall = func(ctx context.Context, _ string) error {
		started.Add(1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil); err != nil {
				t.Errorf("call: %v", err)
			}
		}()
	}
	waitFor(t, func() bool { return started.Load() == 4 })
	time.Sleep(50 * time.Millisecond)
	if started.Load() != 4 {
		t.Fatalf("started = %d while four are in flight, want 4", started.Load())
	}
	close(release)
	wg.Wait()
	if started.Load() != 5 {
		t.Fatalf("started = %d, want 5", started.Load())
	}
}

func TestInitializeHookMismatchRefused(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	cases := map[string]func(r *protocol.InitializeResponse){
		"extra hook": func(r *protocol.InitializeResponse) { r.Hooks["feed.observe"] = protocol.HookDecl{Contract: "feed/1"} },
		"no hooks":   func(r *protocol.InitializeResponse) { r.Hooks = map[string]protocol.HookDecl{} },
		"other contract": func(r *protocol.InitializeResponse) {
			r.Hooks["wire.detect"] = protocol.HookDecl{Contract: "detector/2"}
		},
		"more types": func(r *protocol.InitializeResponse) {
			d := r.Hooks["wire.detect"]
			d.EntityTypes = append(append([]string(nil), d.EntityTypes...), "CARD")
			r.Hooks["wire.detect"] = d
		},
		"other protocol": func(r *protocol.InitializeResponse) { r.Protocol = "basalt-plugin/2" },
		"other name":     func(r *protocol.InitializeResponse) { r.Name = "evil" },
		"other version":  func(r *protocol.InitializeResponse) { r.Version = "9.9.9" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fake{initResp: goodInit(e.Manifest)}
			mutate(f.initResp)
			if err := h.Register(context.Background(), e, f); err == nil {
				t.Fatal("Register accepted a mismatched initialize reply")
			}
			if h.State(e.Key) != StateUnavailable {
				t.Fatal("entry registered despite the mismatch")
			}
		})
	}
	// Order of roles and types does not matter.
	f := &fake{initResp: goodInit(e.Manifest)}
	d := f.initResp.Hooks["wire.detect"]
	d.EntityTypes = []string{"PHONE", "EMAIL"}
	f.initResp.Hooks["wire.detect"] = d
	if err := h.Register(context.Background(), e, f); err != nil {
		t.Fatalf("reordered types refused: %v", err)
	}
}

func TestInitializeRequestHoldsOnlyEntryData(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "product-a", "client-x")
	e.Config = []byte(`{"k":1}`)
	f := register(t, h, e)
	r := f.initReq
	if len(r.Protocols) != 1 || r.Protocols[0] != protocol.Version1 || len(r.Hooks) != 1 || r.Hooks[0] != "wire.detect" {
		t.Fatalf("initialize request = %+v", r)
	}
	if string(r.Config) != `{"k":1}` || r.Limits.MaxInFlight != 4 || r.Limits.MaxMessageBytes != 4<<20 || r.Limits.TimeoutMs != 100 {
		t.Fatalf("initialize request = %+v", r)
	}
}

func TestCallErrorHasNoPayload(t *testing.T) {
	h := NewHost()
	e := entry("acme", "client-x", "a")
	f := register(t, h, e)
	f.onCall = func(context.Context, string) error {
		return errors.New("secret-token jane@example.com")
	}
	err := h.Call(context.Background(), e.Key, []string{"a"}, "detect", map[string]string{"v": "jane@example.com"}, nil)
	var ce *CallError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	if got, want := err.Error(), "plugin acme/client-x: UNAVAILABLE"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if errors.Unwrap(err) != nil {
		t.Fatal("CallError wraps the transport error")
	}
}

func TestTransportClassIsKept(t *testing.T) {
	for _, c := range []FailureClass{ClassExited, ClassBadResponse, ClassOverLimit, ClassUnavailable} {
		h := NewHost()
		e := entry("acme", "default", "a")
		f := register(t, h, e)
		f.onCall = func(context.Context, string) error { return Fail(c) }
		err := h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil)
		assertClass(t, err, c)
		want := StateReady
		if c == ClassExited || c == ClassUnavailable {
			want = StateUnavailable
		}
		if h.State(e.Key) != want {
			t.Errorf("%s: state = %s, want %s", c, h.State(e.Key), want)
		}
	}
}

func TestUnavailableEntryRefusesCalls(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	f := register(t, h, e)
	h.SetState(e.Key, StateUnavailable)
	n := len(f.methods())
	assertClass(t, h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil), ClassUnavailable)
	if len(f.methods()) != n {
		t.Fatal("call reached an unavailable plugin")
	}
	assertClass(t, h.Call(context.Background(), EntryKey{"nope", "default"}, []string{"a"}, "detect", nil, nil), ClassUnavailable)
}

func TestInstancesShareNothing(t *testing.T) {
	h := NewHost()
	ea := entry("acme", "default", "product-a")
	eb := entry("acme", "client-x", "client-x")
	fa := register(t, h, ea)
	fb := register(t, h, eb)

	// Agent lists are per instance.
	if err := h.Call(context.Background(), ea.Key, []string{"client-x"}, "detect", nil, nil); !errors.Is(err, ErrAgentNotListed) {
		t.Fatalf("default served client-x: %v", err)
	}
	// A failure in one leaves the other READY and untouched.
	fb.onCall = func(context.Context, string) error { return Fail(ClassExited) }
	assertClass(t, h.Call(context.Background(), eb.Key, []string{"client-x"}, "detect", nil, nil), ClassExited)
	if h.State(ea.Key) != StateReady || h.State(eb.Key) != StateUnavailable {
		t.Fatalf("states = %s, %s", h.State(ea.Key), h.State(eb.Key))
	}
	// Unregistering one closes only its transport.
	h.Unregister(eb.Key)
	if !fb.closed.Load() || fa.closed.Load() {
		t.Fatal("Unregister closed the wrong transport")
	}
	if err := h.Call(context.Background(), ea.Key, []string{"product-a"}, "detect", nil, nil); err != nil {
		t.Fatalf("default after stopping client-x: %v", err)
	}
	// Each instance has its own in-flight cap: saturating one does not block the other.
	// (Registered again below with its own transport.)
	fb2 := register(t, h, eb)
	block := make(chan struct{})
	fb2.onCall = func(ctx context.Context, _ string) error {
		select {
		case <-block:
		case <-ctx.Done():
		}
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Call(context.Background(), eb.Key, []string{"client-x"}, "detect", nil, nil)
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if err := h.Call(context.Background(), ea.Key, []string{"product-a"}, "detect", nil, nil); err != nil {
		t.Fatalf("saturated sibling blocked default: %v", err)
	}
	close(block)
	wg.Wait()
}

func TestRegisterValidation(t *testing.T) {
	h := NewHost()
	bad := map[string]func(e *Entry){
		"no agents":    func(e *Entry) { e.Agents = nil },
		"wrong name":   func(e *Entry) { e.Manifest.Name = "other" },
		"no instance":  func(e *Entry) { e.Key.Instance = "" },
		"timeout low":  func(e *Entry) { e.Timeout = 49 * time.Millisecond },
		"timeout high": func(e *Entry) { e.Timeout = 60001 * time.Millisecond },
		"verdict hook": func(e *Entry) { e.Manifest.Hooks = map[string]protocol.HookDecl{string(HookWireVerdict): {}} },
		"unknown hook": func(e *Entry) { e.Manifest.Hooks = map[string]protocol.HookDecl{"x.y": {}} },
		"no hooks":     func(e *Entry) { e.Manifest.Hooks = nil },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			e := entry("acme", "default", "a")
			mutate(&e)
			if err := h.Register(context.Background(), e, &fake{initResp: goodInit(manifest("acme"))}); err == nil {
				t.Fatal("Register accepted it")
			}
		})
	}
	e := entry("acme", "default", "a")
	register(t, h, e)
	if err := h.Register(context.Background(), e, &fake{initResp: goodInit(e.Manifest)}); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestDefaultTimeouts(t *testing.T) {
	e := entry("acme", "default", "a")
	e.Timeout = 0
	n, err := normalize(e)
	if err != nil || n.Timeout != 300*time.Millisecond {
		t.Fatalf("local default = %v, %v", n.Timeout, err)
	}
	e.Manifest.Endpoint = Endpoint{Remote: &RemoteEndpoint{Transport: "connectrpc", URL: "https://p.test"}}
	n, err = normalize(e)
	if err != nil || n.Timeout != 2*time.Second {
		t.Fatalf("remote default = %v, %v", n.Timeout, err)
	}
}

func TestHookAllowed(t *testing.T) {
	for _, h := range []Hook{HookWireDetect, HookFeedObserve, HookApprovalDeliver, HookClassifySuggest} {
		if !h.Allowed() {
			t.Errorf("%s not allowed", h)
		}
	}
	for _, h := range []Hook{HookWireVerdict, "nope", ""} {
		if h.Allowed() {
			t.Errorf("%q allowed", h)
		}
	}
}

func TestControlOnlyLifecycle(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	register(t, h, e)
	if err := h.Control(context.Background(), e.Key, protocol.MethodHealth, protocol.HealthRequest{}, &protocol.HealthResponse{}); err != nil {
		t.Fatal(err)
	}
	if err := h.Control(context.Background(), e.Key, "detect", nil, nil); err == nil {
		t.Fatal("Control sent a hook method")
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	e.Timeout = 50 * time.Millisecond
	f := register(t, h, e)
	f.onCall = func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() }
	base := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			if i%2 == 0 {
				go func() { time.Sleep(time.Millisecond); cancel() }()
			}
			_ = h.Call(ctx, e.Key, []string{"a"}, "detect", nil, nil)
			cancel()
		}()
	}
	wg.Wait()
	waitFor(t, func() bool { return runtime.NumGoroutine() <= base+2 })
}

func assertClass(t *testing.T, err error, want FailureClass) {
	t.Helper()
	var ce *CallError
	if !errors.As(err, &ce) || ce.Class != want {
		t.Fatalf("err = %v, want class %s", err, want)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManifestExamplesDecode(t *testing.T) {
	for _, f := range []string{"valid-manifest-local-detector.json", "valid-manifest-remote-classify.json", "valid-manifest-notifier.json"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "plugin", "testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if m.Name == "" || len(m.Hooks) == 0 || (m.Endpoint.Local == nil) == (m.Endpoint.Remote == nil) {
			t.Fatalf("%s decoded to %+v", f, m)
		}
	}
}

// health and shutdown each have a slot of their own: with four hook calls
// holding every hook slot, both are still sent and answered at once.
func TestLifecycleCallsAreOutsideTheCap(t *testing.T) {
	h := NewHost()
	e := entry("acme", "default", "a")
	e.Timeout = 2 * time.Second
	f := register(t, h, e)
	release := make(chan struct{})
	var held atomic.Int32
	f.onCall = func(ctx context.Context, method string) error {
		if method != "detect" {
			return nil
		}
		held.Add(1)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	var wg sync.WaitGroup
	for range protocol.MaxInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.Call(context.Background(), e.Key, []string{"a"}, "detect", nil, nil); err != nil {
				t.Errorf("hook call: %v", err)
			}
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for held.Load() < protocol.MaxInFlight {
		if time.Now().After(deadline) {
			t.Fatal("the four hook calls never started")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	var resp protocol.HealthResponse
	if err := h.Control(ctx, e.Key, protocol.MethodHealth, protocol.HealthRequest{}, &resp); err != nil {
		t.Fatalf("health with four hook calls in flight: %v", err)
	}
	if err := h.Control(ctx, e.Key, protocol.MethodShutdown, protocol.ShutdownRequest{}, nil); err != nil {
		t.Fatalf("shutdown with four hook calls in flight: %v", err)
	}
	if n := held.Load(); n != protocol.MaxInFlight {
		t.Fatalf("hook calls held = %d, want %d", n, protocol.MaxInFlight)
	}
	close(release)
	wg.Wait()
}
