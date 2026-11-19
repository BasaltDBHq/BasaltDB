package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

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
	// Close stops a local plugin at once: ask it to stop first, on a context
	// of its own, so a health call that used up ctx does not skip it.
	shutCtx, shutCancel := context.WithTimeout(context.WithoutCancel(e.c.ctx), entry.Timeout)
	defer shutCancel()
	_ = h.Control(shutCtx, k, protocol.MethodShutdown, protocol.ShutdownRequest{}, nil)
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
