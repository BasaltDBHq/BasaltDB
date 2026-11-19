package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"time"

	plugincontract "github.com/basaltdbhq/basaltdb/api/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	"github.com/basaltdbhq/basaltdb/internal/plugin/dial"
	"github.com/basaltdbhq/basaltdb/internal/plugin/protocol"
)

// pluginKeygen: basalt plugin keygen --out DIR. An author command: it
// reads no engine.json and is not a consent action, so an agent may run
// it. The private key is written mode 0600 and never printed.
func pluginKeygen(c *cliIO, args []string) int {
	fs := c.flags("plugin keygen")
	out := fs.String("out", "", "the directory to write <keyId>.key and <keyId>.pub to (required)")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	if *out == "" {
		return c.fail(fmt.Errorf("%w: --out DIR is required", errUsage))
	}
	dir, err := filepath.Abs(*out)
	if err != nil {
		return c.fail(err)
	}
	keys, err := plugin.WriteKeyPair(dir)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "key id %s\npublic key %s\n", keys.KeyID, keys.PublicPath)
	fmt.Fprintf(c.stderr, "basalt: the private key is %s (mode 0600); keep it secret and never share it. "+
		"Sign a plugin with: basalt plugin sign <dir> --key %s\n", keys.PrivatePath, shellQuote(keys.PrivatePath))
	return exitOK
}

// pluginSign: basalt plugin sign <dir> --key FILE. An author command, like
// keygen.
func pluginSign(c *cliIO, args []string) int {
	fs := c.flags("plugin sign")
	key := fs.String("key", "", "the private key file to sign with, mode 0600 (required)")
	dir, err := parseOne(fs, args, "the plugin's directory")
	if err != nil {
		return c.fail(err)
	}
	if *key == "" {
		return c.fail(fmt.Errorf("%w: --key FILE is required", errUsage))
	}
	if dir, err = filepath.Abs(dir); err != nil {
		return c.fail(err)
	}
	priv, err := plugin.ReadSigningKey(*key)
	if err != nil {
		return c.fail(err)
	}
	sigPath, id, err := plugin.SignDir(dir, priv)
	if err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "signed by key %s\nsignature %s\n", id, sigPath)
	return exitOK
}

// checkWait bounds starting or dialing the plugin for basalt plugin check;
// each call then has the entry's own timeoutMs.
const checkWait = 30 * time.Second

func pluginCheck(c *cliIO, args []string) int {
	e, k, asJSON, code := entryFlags(c, "check", args, true)
	if code >= 0 {
		return code
	}
	return c.pluginDone(e.check(k), asJSON)
}

// check starts entry k from its verified installed copy, runs initialize
// and health, sends each declared notifier hook its fixed sample, prints the
// timing and sends shutdown. It sends no store data and needs no database,
// and changes nothing of the engine's, so an agent may run it. A notifier
// receives the samples as it would real events, marked by their install id.
func (e *pluginEnv) check(k plugin.EntryKey) error {
	p, err := e.entry(k)
	if err != nil {
		return err
	}
	v, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode)
	if err != nil {
		return e.verifyRefusal(err, e.command("check", entryArgs(k)...))
	}
	entry, err := p.Entry(v.Manifest)
	if err != nil {
		return err
	}
	if !v.Manifest.Endpoint.IsRemote() && e.mode == plugin.ModeService {
		return fmt.Errorf("plugin %s: in service mode a local plugin runs as its own OS user under its own service, "+
			"which basalt plugin check does not start yet. There the plugin must listen on the socket BASALT_PLUGIN_SOCKET names "+
			"(a plugin built with the Go SDK does); one that only reads stdin never starts", k)
	}
	if !v.Manifest.Endpoint.IsRemote() && e.c.host.Euid() == 0 {
		return fmt.Errorf("plugin %s: a local plugin is never started with root's privileges; "+
			"run basalt plugin check as the engine's own OS user", k)
	}
	ctx, cancel := context.WithTimeout(e.c.ctx, checkWait)
	defer cancel()
	// A socket plugin listens in a fresh directory only this user can reach
	// (dial.Options.SocketBase), removed when it stops.
	t, err := dial.Entry(ctx, k, v, dial.Options{CredentialFile: p.CredentialFile()})
	if err != nil {
		return err
	}
	h := plugin.NewHost()
	start := time.Now()
	if err := h.Register(ctx, entry, t); err != nil {
		_ = t.Close()
		return fmt.Errorf("plugin %s: initialize failed: %w", k, err)
	}
	initDur := time.Since(start)
	defer h.Unregister(k)
	start = time.Now()
	var health protocol.HealthResponse
	err = h.Control(ctx, k, protocol.MethodHealth, protocol.HealthRequest{}, &health)
	healthDur := time.Since(start)
	var hookErr error
	if err == nil {
		fmt.Fprintf(e.c.stdout, "plugin %s: initialize %s, health %s %s\n", k, roundMs(initDur), visibleText(health.Status), roundMs(healthDur))
		if health.Status == protocol.HealthReady {
			hookErr = e.checkHooks(ctx, h, entry)
		}
	}
	// Close stops a local plugin at once: ask it to stop first, on a context
	// of its own, so a call that used up ctx does not skip it.
	shutCtx, shutCancel := context.WithTimeout(context.WithoutCancel(e.c.ctx), entry.Timeout)
	defer shutCancel()
	_ = h.Control(shutCtx, k, protocol.MethodShutdown, protocol.ShutdownRequest{}, nil)
	if err != nil {
		return fmt.Errorf("plugin %s: health failed: %w", k, err)
	}
	if health.Status != protocol.HealthReady {
		return fmt.Errorf("plugin %s answered health %s", k, visibleText(health.Status))
	}
	return hookErr
}

// checkHooks sends each declared notifier hook the contract's fixed sample,
// for the entry's first agent, and prints one timing line per hook. The
// samples hold no store data. It stops at the first hook that fails.
func (e *pluginEnv) checkHooks(ctx context.Context, h *plugin.Host, entry plugin.Entry) error {
	k := entry.Key
	agent := entry.Agents[0]
	for _, hook := range hookNamesSorted(entry.Manifest) {
		switch plugin.Hook(hook) {
		case plugin.HookApprovalDeliver:
			params, err := checkDeliverParams(agent, time.Now())
			if err != nil {
				return err
			}
			start := time.Now()
			if err := h.DeliverApproval(ctx, k, agent, params.Event); err != nil {
				return fmt.Errorf("plugin %s: %s failed: %w", k, hook, err)
			}
			fmt.Fprintf(e.c.stdout, "plugin %s: %s %s\n", k, hook, roundMs(time.Since(start)))
		case plugin.HookFeedObserve:
			params, err := checkFeedParams(agent)
			if err != nil {
				return err
			}
			start := time.Now()
			last, err := h.ObserveFeed(ctx, k, agent, params.Events)
			if err != nil {
				return fmt.Errorf("plugin %s: %s failed: %w", k, hook, err)
			}
			dur := time.Since(start)
			if last != plugincontract.CheckFeedLastSeq {
				return fmt.Errorf("plugin %s: %s failed: %s: answered lastSeq %d; the sample's events end at seq %d, and a plugin that handles them answers it",
					k, hook, plugin.ClassBadResponse, last, plugincontract.CheckFeedLastSeq)
			}
			fmt.Fprintf(e.c.stdout, "plugin %s: %s lastSeq %d %s\n", k, hook, last, roundMs(dur))
		case plugin.HookWireDetect, plugin.HookClassifySuggest, plugin.HookWireVerdict:
			// No fixed sample for these hooks yet.
		}
	}
	return nil
}

func hookNamesSorted(m plugin.Manifest) []string {
	return slices.Sorted(maps.Keys(m.Hooks))
}

// checkFeedParams is the contract's feed sample for agent: byte for byte,
// but for the agent it names.
func checkFeedParams(agent string) (protocol.FeedObserveRequest, error) {
	b, err := replaceSample(plugincontract.CheckFeedSample(), sampleAgent(agent))
	if err != nil {
		return protocol.FeedObserveRequest{}, err
	}
	var out protocol.FeedObserveRequest
	err = json.Unmarshal(b, &out)
	return out, err
}

// checkDeliverParams is the contract's notice sample for agent, made at now
// and expiring an hour later.
func checkDeliverParams(agent string, now time.Time) (protocol.ApprovalDeliverRequest, error) {
	now = now.UTC().Truncate(time.Millisecond)
	b, err := replaceSample(plugincontract.CheckDeliverSample(), append(sampleAgent(agent),
		sampleReplace{`"time": "` + plugincontract.CheckSampleTime + `"`, `"time": "` + now.Format(time.RFC3339Nano) + `"`, 1},
		sampleReplace{`"expiresAt": "` + plugincontract.CheckSampleExpiresAt + `"`, `"expiresAt": "` + now.Add(time.Hour).Format(time.RFC3339Nano) + `"`, 1},
	))
	if err != nil {
		return protocol.ApprovalDeliverRequest{}, err
	}
	var out protocol.ApprovalDeliverRequest
	err = json.Unmarshal(b, &out)
	return out, err
}

type sampleReplace struct {
	old, new string
	// at least is how many times old must occur.
	atLeast int
}

func sampleAgent(agent string) []sampleReplace {
	q, _ := json.Marshal(agent)
	return []sampleReplace{{`"` + plugincontract.CheckSampleAgent + `"`, string(q), 3}}
}

// replaceSample swaps exact byte strings in a sample, so every other byte is
// the contract's. A sample that no longer holds what is swapped is an error.
func replaceSample(b []byte, rs []sampleReplace) ([]byte, error) {
	for _, r := range rs {
		if bytes.Count(b, []byte(r.old)) < r.atLeast {
			return nil, fmt.Errorf("basalt: the check sample no longer holds %s", r.old)
		}
		b = bytes.ReplaceAll(b, []byte(r.old), []byte(r.new))
	}
	return b, nil
}

func roundMs(d time.Duration) string { return d.Round(time.Millisecond).String() }
