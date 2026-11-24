// Command basalt-test-notifier is the engine tests' notifier plugin, with
// fault modes. Package testnotifier builds and drives it; its doc says how.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	basaltplugin "github.com/basaltdbhq/basalt-plugin-go"

	tn "github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/testnotifier"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet(tn.Binary, flag.ContinueOnError)
	mode := fs.String("mode", envOr(tn.EnvMode, string(tn.ModeOK)), "how hook calls are answered")
	record := fs.String("record", os.Getenv(tn.EnvRecord), "the file every hook call is appended to")
	control := fs.String("control", os.Getenv(tn.EnvControl), "a file holding the mode, read at start and at every call")
	delay := fs.Duration("delay", envDuration(tn.EnvDelay, tn.DefaultDelay), "the late mode's delay")
	hooks := fs.String("hooks", envOr(tn.EnvHooks, tn.HookFeedObserve+","+tn.HookApprovalDeliver), "the hooks it declares")
	transport := fs.String("transport", "", "jsonrpc-stdio, jsonrpc-unix or connectrpc")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	n := &notifier{start: tn.Mode(*mode), control: *control, delay: *delay, rec: &recorder{path: *record}}
	feed, deliver := false, false
	for _, h := range strings.Split(*hooks, ",") {
		switch h {
		case tn.HookFeedObserve:
			feed = true
		case tn.HookApprovalDeliver:
			deliver = true
		default:
			fmt.Fprintln(os.Stderr, tn.Binary+": unknown hook", h)
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if m := n.mode(); m == tn.ModeBadSeq || m == tn.ModeBadJSON {
		if *transport == string(basaltplugin.ConnectRPC) {
			fmt.Fprintln(os.Stderr, tn.Binary+": "+string(m)+" is served on JSON-RPC transports only")
			return 2
		}
		if err := serveRaw(ctx, n, m, feed, deliver); err != nil {
			fmt.Fprintln(os.Stderr, tn.Binary+":", err)
			return 1
		}
		return 0
	}

	var p basaltplugin.Plugin
	switch {
	case feed && deliver:
		p = both{n}
	case feed:
		p = feedOnly{n}
	case deliver:
		p = deliverOnly{n}
	}
	var opts []basaltplugin.Option
	if *transport != "" {
		opts = append(opts, basaltplugin.WithTransport(basaltplugin.Transport(*transport)))
	}
	if err := basaltplugin.Serve(ctx, p, opts...); err != nil {
		fmt.Fprintln(os.Stderr, tn.Binary+":", err)
		return 1
	}
	return 0
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(key)); err == nil {
		return d
	}
	return def
}

// notifier holds the settings and answers by mode.
type notifier struct {
	start   tn.Mode
	control string
	delay   time.Duration
	rec     *recorder
}

// mode is the control file's mode when it holds one, else the start mode.
func (n *notifier) mode() tn.Mode {
	if n.control != "" {
		if b, err := os.ReadFile(n.control); err == nil {
			if m := strings.TrimSpace(string(b)); m != "" {
				return tn.Mode(m)
			}
		}
	}
	return n.start
}

func (n *notifier) Info() basaltplugin.Info {
	return basaltplugin.Info{Name: tn.Name, Version: tn.Version}
}

func (n *notifier) Health(context.Context) error {
	if n.mode() == tn.ModeNotReady {
		return errors.New("not ready")
	}
	return nil
}

var errRawMode = errors.New("a raw mode takes effect when the plugin starts")

// behave records the call, then acts on the mode. It returns an error for a
// call that must fail.
func (n *notifier) behave(r tn.Record) error {
	m := n.mode()
	r.Mode = m
	n.rec.write(r)
	switch m {
	case tn.ModeOK, tn.ModeNotReady:
	case tn.ModeLate:
		time.Sleep(n.delay)
	case tn.ModeHang:
		select {}
	case tn.ModeCrash:
		os.Exit(tn.CrashExit)
	case tn.ModeBadSeq, tn.ModeBadJSON:
		return errRawMode
	}
	return nil
}

func (n *notifier) observe(_ context.Context, b basaltplugin.FeedBatch) (int64, error) {
	r := tn.Record{Hook: tn.HookFeedObserve, Agent: b.Agent}
	for _, ev := range b.Events {
		r.Events = append(r.Events, ev.Raw())
	}
	if err := n.behave(r); err != nil {
		return 0, err
	}
	return b.LastSeq(), nil
}

func (n *notifier) deliver(_ context.Context, notice basaltplugin.Notice) error {
	return n.behave(tn.Record{Hook: tn.HookApprovalDeliver, Agent: notice.Agent, Event: notice.Raw()})
}

// The SDK declares a hook for each interface a plugin implements, so each set
// of hooks is its own type.
type (
	feedOnly    struct{ *notifier }
	deliverOnly struct{ *notifier }
	both        struct{ *notifier }
)

func (p feedOnly) ObserveFeed(ctx context.Context, b basaltplugin.FeedBatch) (int64, error) {
	return p.observe(ctx, b)
}

func (p deliverOnly) DeliverApproval(ctx context.Context, n basaltplugin.Notice) error {
	return p.deliver(ctx, n)
}

func (p both) ObserveFeed(ctx context.Context, b basaltplugin.FeedBatch) (int64, error) {
	return p.observe(ctx, b)
}

func (p both) DeliverApproval(ctx context.Context, n basaltplugin.Notice) error {
	return p.deliver(ctx, n)
}
