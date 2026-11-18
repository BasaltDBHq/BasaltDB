package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
	pluginconnect "github.com/basaltdbhq/basaltdb/internal/plugin/connect"
	"github.com/basaltdbhq/basaltdb/internal/plugin/jsonrpc"
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
// and health, prints the timing and sends shutdown. It sends no store data
// and needs no database. It changes nothing, so an agent may run it.
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
			"which basalt plugin check does not start yet", k)
	}
	ctx, cancel := context.WithTimeout(e.c.ctx, checkWait)
	defer cancel()
	t, err := dialPlugin(ctx, v, p)
	if err != nil {
		return err
	}
	h := plugin.NewHost()
	start := time.Now()
	if err := h.Register(entry, t); err != nil {
		_ = t.Close()
		return fmt.Errorf("plugin %s: initialize failed: %w", k, err)
	}
	initDur := time.Since(start)
	defer h.Unregister(k)
	start = time.Now()
	var health protocol.HealthResponse
	err = h.Control(ctx, k, protocol.MethodHealth, protocol.HealthRequest{}, &health)
	healthDur := time.Since(start)
	// Close stops a local plugin at once: ask it to stop first.
	_ = h.Control(ctx, k, protocol.MethodShutdown, protocol.ShutdownRequest{}, nil)
	if err != nil {
		return fmt.Errorf("plugin %s: health failed: %w", k, err)
	}
	fmt.Fprintf(e.c.stdout, "plugin %s: initialize %s, health %s %s\n", k, roundMs(initDur), visibleText(health.Status), roundMs(healthDur))
	if health.Status != protocol.HealthReady {
		return fmt.Errorf("plugin %s answered health %s", k, visibleText(health.Status))
	}
	return nil
}

func roundMs(d time.Duration) string { return d.Round(time.Millisecond).String() }

// Transports a local plugin may declare.
const (
	transportStdio   = "jsonrpc-stdio"
	transportUnix    = "jsonrpc-unix"
	transportConnect = "connectrpc"
)

// errNotServed: this build cannot reach the plugin this way yet.
var errNotServed = errors.New("is not served by this build yet")

// dialPlugin reaches the installed copy v of entry p over the transport its
// manifest names: a remote plugin through the connectrpc adapter (TLS to
// the declared host only, with the entry's credential file), a local
// jsonrpc-stdio plugin as a child process with an empty environment and its
// stderr discarded.
func dialPlugin(ctx context.Context, v plugin.Verified, p config.Plugin) (plugin.Transport, error) {
	k, m := p.Key(), v.Manifest
	if r := m.Endpoint.Remote; r != nil {
		t, err := pluginconnect.Dial(ctx, *r, m.Network.Egress, p.CredentialFile())
		if err != nil {
			return nil, fmt.Errorf("plugin %s: %w", k, err)
		}
		return t, nil
	}
	l := m.Endpoint.Local
	switch l.Transport {
	case transportStdio:
		t, err := jsonrpc.Spawn(ctx, filepath.Join(v.Dir, filepath.FromSlash(l.Command)), l.Args, nil)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: the plugin's command could not be started", k)
		}
		return t, nil
	case transportUnix:
		return nil, fmt.Errorf("plugin %s: a local jsonrpc-unix plugin %w", k, errNotServed)
	default:
		return nil, fmt.Errorf("plugin %s: a local %s plugin %w", k, visibleText(l.Transport), errNotServed)
	}
}
