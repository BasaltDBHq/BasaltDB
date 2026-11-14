package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engineaddr"
)

// defaultDirectAddr is the address the commands forward to when the
// engine's config does not say: the one basalt init --direct-addr documents.
const defaultDirectAddr = "127.0.0.1:8787"

// examplePublicHost stands for the person's own name in the commands when
// no --address is given.
const examplePublicHost = "engine.example.com"

// tunnelProbeTimeout bounds the check of the public address; a tunnel
// across the internet is slower than the loopback probes.
const tunnelProbeTimeout = 10 * time.Second

// maxProbeAnswer is the most of /v1/engine's answer the check reads: the
// answer is two short fields.
const maxProbeAnswer = 4 << 10

// directHostRefusal is the whole body of the direct listener's refusal of a
// Host it does not record. The local pages answer "host not allowed: <host>",
// so a match on the whole body tells the two listeners apart.
const directHostRefusal = "host not allowed"

// cloudflareTunnelDown is Cloudflare's status for a tunnel that is not connected.
const cloudflareTunnelDown = 530

// probeAnswer is what GET <address>/v1/engine gave: the status, the body
// (at most maxProbeAnswer bytes) and whether it was JSON.
type probeAnswer struct {
	status int
	json   bool
	body   []byte
}

// engineProbe fetches url with no Origin, no credentials and no redirect,
// as the CLI's check of the probe route (CONTRACT.md, Direct transport).
func engineProbe(ctx context.Context, url string) (probeAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, tunnelProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return probeAnswer{}, err
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return probeAnswer{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeAnswer))
	if err != nil {
		return probeAnswer{}, err
	}
	return probeAnswer{status: resp.StatusCode, json: strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"), body: body}, nil
}

// runTunnel: basalt tunnel (CONTRACT.md, CLI). Prints the commands that
// publish the engine's direct listener (Cloudflare Tunnel, Tailscale
// Funnel, Caddy) and, given the address they publish, checks that it
// answers and serves this engine's key.
func runTunnel(c *cliIO, args []string) int {
	fs := c.flags("tunnel")
	address := fs.String("address", "", "the https address your tunnel publishes (https://<host>[:<port>]); checks that it answers with this engine's key")
	listen := fs.String("direct-addr", "", "the loopback host:port the tunnel forwards to (default: directAddr in engine.json, else "+defaultDirectAddr+")")
	configPath := fs.String("config", config.DefaultPath(c.goos), "engine config file, to read directAddr and the engine's key")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	public := ""
	if *address != "" {
		a, err := engineaddr.Parse(*address)
		if err != nil {
			return c.fail(fmt.Errorf("%w: --address: %w", errUsage, err))
		}
		public = a
	}
	cfgPath := configOrFallback(c.host, fs, *configPath)
	to, err := tunnelTarget(c, *listen, cfgPath)
	if err != nil {
		return c.fail(err)
	}
	host := examplePublicHost
	if public != "" {
		host = strings.TrimPrefix(public, "https://")
	}
	// DNS names have no port.
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	fmt.Fprint(c.stdout, tunnelGuide(to, host, public))
	if public == "" {
		return exitOK
	}
	return c.checkTunnel(public, localEngineID(c, cfgPath))
}

// tunnelTarget is the loopback address the commands forward to: --direct-addr,
// else directAddr in the engine's config, else defaultDirectAddr. What is not
// the config's own value is said on stderr, so the person knows the engine
// still needs it (basalt init --direct-addr, then a restart).
func tunnelTarget(c *cliIO, given, cfgPath string) (string, error) {
	if given != "" {
		if err := checkDirectAddr(given); err != nil {
			return "", err
		}
		if given == config.PagesOff {
			return "", fmt.Errorf("%w: --direct-addr off has nothing to forward to; give a loopback host:port", errUsage)
		}
		return given, nil
	}
	cfg, err := loadEngineConfig(c, cfgPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "basalt: engine.json not read here (%v); using %s, the address basalt init --direct-addr takes\n", err, defaultDirectAddr)
		return defaultDirectAddr, nil
	}
	to, err := cfg.Direct()
	switch {
	case err != nil:
		return "", err
	case to == "":
		fmt.Fprintf(c.stderr, "basalt: directAddr is off in %s, so the engine has no listener yet. On the engine's machine run "+
			"basalt init --remote --agent NAME --direct-addr %s, then restart the engine; the commands below forward to that address\n", cfgPath, defaultDirectAddr)
		return defaultDirectAddr, nil
	}
	return to, nil
}

// checkTunnel checks that public answers GET /v1/engine with a key whose id
// is the id of the key (wantID, "" when this machine's key file was not
// read), and prints what the person does next. It returns the exit code.
func (c *cliIO) checkTunnel(public, wantID string) int {
	ans, err := c.probe(c.ctx, public+"/v1/engine")
	if err != nil {
		return c.fail(fmt.Errorf("%s does not answer: %w (is the tunnel running, and does its name point at it?)", public, err))
	}
	id, err := judgeProbe(public, ans)
	if err != nil {
		return c.fail(err)
	}
	if wantID != "" && id != wantID {
		return c.fail(fmt.Errorf("%s answers, but with another engine's key (%s); this engine's is %s: the tunnel reaches a different engine",
			public, channel.FingerprintOf(id), channel.FingerprintOf(wantID)))
	}
	fmt.Fprintf(c.stdout, "%s answers and serves ", public)
	if wantID != "" {
		fmt.Fprintf(c.stdout, "this engine's key.\n")
	} else {
		fmt.Fprintf(c.stdout, "an engine's key (this machine's key file was not read; compare the fingerprint with basalt status on the engine's machine).\n")
	}
	fmt.Fprintf(c.stdout, "Engine fingerprint: %s\n\n", channel.FingerprintOf(id))
	fmt.Fprintf(c.stdout, "Next, on your own computer:\n"+
		"  1. For each agent whose database does not record the address yet: basalt init --setup-code <the agent's code> --engine-url %s\n"+
		"  2. On each device you approve from, pin it at %s/add and compare the fingerprint above.\n", public, pinPageURL)
	return exitOK
}

// judgeProbe turns the answer of /v1/engine into the engine's id, or says
// what is wrong in terms of the tunnel.
func judgeProbe(public string, ans probeAnswer) (string, error) {
	switch {
	case ans.status == http.StatusBadRequest && strings.TrimSpace(string(ans.body)) == directHostRefusal:
		return "", fmt.Errorf("%s reaches the engine's direct listener, but the engine does not know the Host it was given: record the address first with "+
			"basalt init --setup-code <the agent's code> --engine-url %s on your own computer and run this again (the engine reads the records every 10 seconds); "+
			"if you recorded it already, the tunnel does not pass the public Host on unchanged, or the recorded address has another port", public, public)
	case ans.status == http.StatusBadGateway || ans.status == http.StatusServiceUnavailable || ans.status == http.StatusGatewayTimeout || ans.status == cloudflareTunnelDown:
		return "", fmt.Errorf("%s answers %d: the tunnel is not connected to the engine's direct listener; check that the tunnel runs, that the engine runs with directAddr, and that the tunnel forwards to it", public, ans.status)
	case ans.status != http.StatusOK:
		return "", fmt.Errorf("%s answers %d to /v1/engine: that is not the engine's direct listener (the tunnel may forward to the local pages instead of directAddr)", public, ans.status)
	case !ans.json:
		return "", fmt.Errorf("%s answers /v1/engine with something that is not JSON: that is not the engine's direct listener", public)
	}
	var out struct {
		EngineKey string `json:"engineKey"`
		EngineID  string `json:"engineId"`
	}
	if err := json.Unmarshal(ans.body, &out); err != nil {
		return "", fmt.Errorf("%s answers /v1/engine with JSON basalt cannot read: %w", public, err)
	}
	key, err := base64.RawURLEncoding.DecodeString(out.EngineKey)
	if err != nil || len(key) == 0 || channel.EngineIDOf(key) != out.EngineID {
		return "", fmt.Errorf("%s answers with an engine id that is not the hash of its key: do not pin it", public)
	}
	return out.EngineID, nil
}

// tunnelGuide is the three ways to publish to, in the order the contract
// names them. Each must pass the public Host on unchanged: the engine
// answers only on the address the database records.
func tunnelGuide(to, host, public string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Publish the engine's direct listener, %s, at an https address of your own. Pick one.\n", to)
	b.WriteString("The tunnel must pass the public Host unchanged and upgrade WebSockets; all three do by default.\n\n")
	b.WriteString("Cloudflare Tunnel (a domain on Cloudflare):\n")
	fmt.Fprintf(&b, "  cloudflared tunnel login    # once\n  cloudflared tunnel create basalt-engine\n  cloudflared tunnel route dns basalt-engine %s\n  cloudflared tunnel run --url http://%s basalt-engine\n\n", host, to)
	b.WriteString("Tailscale Funnel (an address like <machine>.<tailnet>.ts.net, with Funnel enabled for it; Funnel serves on 443, 8443 and 10000):\n")
	fmt.Fprintf(&b, "  tailscale funnel --bg http://%s\n  tailscale funnel status    # shows the address\n\n", to)
	b.WriteString("Caddy (a server with a public name pointing at it; Caddy gets the certificate):\n")
	fmt.Fprintf(&b, "  %s {\n      reverse_proxy %s\n  }\n\n", host, to)
	if public == "" {
		fmt.Fprintf(&b, "Then run basalt tunnel --address https://%s with your own address to check it.\n", host)
	}
	return b.String()
}
