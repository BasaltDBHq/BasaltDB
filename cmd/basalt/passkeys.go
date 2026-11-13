package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// minIDPrefix is the shortest credential id prefix basalt passkey remove
// accepts, so a typo cannot match a passkey by chance.
const minIDPrefix = 8

// dateLayout is how passkey dates are printed.
const dateLayout = "2006-01-02"

// runPasskey: basalt passkey list | remove | check (CONTRACT.md, Passkey
// management). WebAuthn never tells the server a passkey was deleted, so
// the person lists, checks and removes passkeys here.
func runPasskey(c *cliIO, args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("%w: basalt passkey list | remove <credentialId> | check", errUsage))
	}
	switch args[0] {
	case "list":
		return passkeyList(c, args[1:])
	case "remove":
		return passkeyRemove(c, args[1:])
	case "check":
		return passkeyCheck(c, args[1:])
	}
	return c.fail(fmt.Errorf("%w: unknown passkey command %q (list, remove, check)", errUsage, args[0]))
}

// agentFlags are the flags that find the agent credential, as for basalt log.
type agentFlags struct {
	agent, configPath, credFile *string
}

func addAgentFlags(c *cliIO, name string) (*flag.FlagSet, agentFlags) {
	fs := c.flags(name)
	return fs, agentFlags{
		agent:      fs.String("agent", "", "use this agent's credential from the engine config"),
		configPath: fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file"),
		credFile:   fs.String("credential-file", "", "read the agent's connection string from this file"),
	}
}

// passkeys lists the active passkeys with the agent the flags name: over
// the person socket in service mode, else with the agent's credential.
func (f agentFlags) passkeys(c *cliIO) ([]ledger.Passkey, error) {
	l, err := openLedger(c, *f.agent, *f.credFile, *f.configPath)
	if err != nil {
		return nil, err
	}
	defer l.close()
	return l.ListPasskeys(c.ctx)
}

// passkeyDTO is one passkey in basalt passkey list --json: public data
// only, never key material.
type passkeyDTO struct {
	CredentialID string     `json:"credentialId"`
	Label        string     `json:"label"`
	RPID         string     `json:"rpId"`
	Origin       string     `json:"origin"`
	CreatedAt    time.Time  `json:"createdAt"`
	LastUsedAt   *time.Time `json:"lastUsedAt"`
}

func passkeyFromDomain(k ledger.Passkey) passkeyDTO {
	return passkeyDTO{
		CredentialID: passkey.Bytes(k.Credential.ID).String(), Label: k.Label,
		RPID: k.Credential.Relying.RPID, Origin: k.Credential.Relying.Origin,
		CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
	}
}

func passkeyList(c *cliIO, args []string) int {
	fs, af := addAgentFlags(c, "passkey list")
	asJSON := fs.Bool("json", false, "print the passkeys as JSON")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	keys, err := af.passkeys(c)
	if err != nil {
		return c.fail(err)
	}
	out := make([]passkeyDTO, 0, len(keys))
	for _, k := range keys {
		out = append(out, passkeyFromDomain(k))
	}
	if *asJSON {
		return printJSONValue(c, out)
	}
	if len(out) == 0 {
		fmt.Fprintln(c.stderr, "basalt: no active passkey; register one with basalt init --add-passkey")
		return exitOK
	}
	for _, k := range out {
		fmt.Fprintf(c.stdout, "%s  %-20s %-16s registered %s  last used %s\n",
			k.CredentialID, k.Label, k.RPID, k.CreatedAt.UTC().Format(dateLayout), lastUsed(k.LastUsedAt))
	}
	return exitOK
}

func lastUsed(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(dateLayout)
}

// removeFlags are basalt passkey remove's options.
type removeFlags struct {
	force, yes bool
	// pagesURL is the forget page's base; "" means the passkey's own
	// registered origin, the only one that can signal about it.
	pagesURL string
	open     bool
}

func passkeyRemove(c *cliIO, args []string) int {
	fs := c.flags("passkey remove")
	var f removeFlags
	fs.BoolVar(&f.force, "force", false, "allow removing the last active passkey (asks you to type its label)")
	fs.BoolVar(&f.yes, "yes", false, "do not ask for confirmation (the last passkey still asks for its label)")
	pagesURLFlag(fs, &f.pagesURL, "pages base URL of the forget link (default: the origin the passkey was registered with)")
	fs.BoolVar(&f.open, "open", false, "open the forget link in the default browser instead of printing it")
	if err := fs.Parse(idAfterFlags(fs, args)); err != nil {
		return c.fail(fmt.Errorf("%w: %w", errUsage, err))
	}
	if fs.NArg() != 1 {
		return c.fail(fmt.Errorf("%w: give one credential id (basalt passkey list shows them)", errUsage))
	}
	id := fs.Arg(0)
	conn, err := connectAdmin(c)
	if err != nil {
		return c.fail(err)
	}
	defer conn.Close(c.ctx)
	keys, err := guard.ActivePasskeys(c.ctx, conn)
	if err != nil {
		return c.fail(err)
	}
	k, err := findPasskey(keys, id)
	if err != nil {
		return c.fail(err)
	}
	if err := removePasskey(c, conn, keys, k, f); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// idAfterFlags moves a credential id that starts with "-" behind "--".
// base64url includes "-", so about one id in 64 looks like a flag to the
// flag package and would be refused as one. An argument that starts with
// one or more dashes is taken as an id only when it is at least minIDPrefix
// characters of base64url (the dashes included) and names no flag. The scan
// stops at "--" (what follows is already positional) and skips the value of
// a flag that takes one, so a value that starts with "-" is never taken as
// the id.
func idAfterFlags(fs *flag.FlagSet, args []string) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return args
		}
		if takesSeparateValue(fs, a) {
			i++
			continue
		}
		if !looksLikeID(fs, a) {
			continue
		}
		rest := append(append([]string{}, args[:i]...), args[i+1:]...)
		return append(rest, "--", a)
	}
	return args
}

// takesSeparateValue is whether a names a non-boolean flag of fs without an
// "=value", so the flag package reads the next argument as its value.
func takesSeparateValue(fs *flag.FlagSet, a string) bool {
	name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
	if name == a || strings.Contains(name, "=") {
		return false
	}
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
		return false
	}
	return true
}

func looksLikeID(fs *flag.FlagSet, a string) bool {
	if len(a) < minIDPrefix || a[0] != '-' {
		return false
	}
	// The flag package reads "-name" and "--name" alike: neither is an id.
	name := strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
	if fs.Lookup(name) != nil {
		return false
	}
	return strings.Trim(a, base64URLAlphabet) == ""
}

const base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// connectAdmin opens the admin connection (env or hidden prompt, never stored).
func connectAdmin(c *cliIO) (*pgx.Conn, error) {
	dsn, err := c.adminURL()
	if err != nil {
		return nil, err
	}
	return connect(c.ctx, dsn)
}

// findPasskey is the active passkey whose base64url id is id or starts
// with it (at least minIDPrefix characters, matching exactly one).
func findPasskey(keys []guard.RegisteredPasskey, id string) (guard.RegisteredPasskey, error) {
	var match []guard.RegisteredPasskey
	for _, k := range keys {
		text := passkey.Bytes(k.ID).String()
		if text == id {
			return k, nil
		}
		if len(id) >= minIDPrefix && strings.HasPrefix(text, id) {
			match = append(match, k)
		}
	}
	switch len(match) {
	case 0:
		return guard.RegisteredPasskey{}, fmt.Errorf("no active passkey %q (give the id, or at least %d of its first characters, as basalt passkey list shows it)", id, minIDPrefix)
	case 1:
		return match[0], nil
	}
	return guard.RegisteredPasskey{}, fmt.Errorf("%q matches %d passkeys; give more of the id", id, len(match))
}

// removePasskey confirms, revokes k in Postgres, and prints the forget
// link for the devices that hold it.
func removePasskey(c *cliIO, conn *pgx.Conn, keys []guard.RegisteredPasskey, k guard.RegisteredPasskey, f removeFlags) error {
	idText := passkey.Bytes(k.ID).String()
	fmt.Fprintf(c.stderr, "basalt: passkey %q (%s) for %s, registered %s, last used %s\n",
		k.Label, idText, k.RPID, k.CreatedAt.UTC().Format(dateLayout), lastUsed(k.LastUsedAt))
	last := len(keys) == 1
	if err := confirmRemoval(c, k, last, f); err != nil {
		return err
	}
	remaining, err := guard.RevokePasskey(c.ctx, conn, k.ID, last && f.force)
	if err != nil {
		return fmt.Errorf("the database refused: %s", pgDetail(err))
	}
	fmt.Fprintf(c.stderr, "basalt: passkey %q revoked; it can no longer approve or revert. %d active passkeys remain.\n", k.Label, remaining)
	if remaining == 0 {
		fmt.Fprintln(c.stderr, "basalt: register another with basalt init --add-passkey before the next held write")
	}
	return forgetLink(c, keys, k, f)
}

// confirmRemoval asks unless --yes; the last active passkey needs --force
// and its label typed, --yes or not.
func confirmRemoval(c *cliIO, k guard.RegisteredPasskey, last bool, f removeFlags) error {
	if last {
		if !f.force {
			return errors.New("this is the last active passkey: nothing held could be approved or reverted without one. Register another first (basalt init --add-passkey), or pass --force")
		}
		fmt.Fprintf(c.stderr, "This is the last active passkey. Type its label (%s) to remove it: ", k.Label)
		typed, err := c.line()
		if err != nil || typed != k.Label {
			return errors.New("the label did not match; nothing was removed")
		}
		return nil
	}
	if f.yes {
		return nil
	}
	ok, err := c.confirm(fmt.Sprintf("Remove passkey %q?", k.Label))
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("nothing was removed")
	}
	return nil
}

// forgetLink prints (or with --open opens) the page that asks a device's
// password manager to drop the removed passkey (WebAuthn Signal API, where
// supported). Only a page on the passkey's registered origin can signal
// about it, so another --pages-url gets no link.
func forgetLink(c *cliIO, keys []guard.RegisteredPasskey, removed guard.RegisteredPasskey, f removeFlags) error {
	base := strings.TrimSuffix(f.pagesURL, "/")
	if base == "" {
		base = removed.Origin
	}
	if base != removed.Origin {
		fmt.Fprintf(c.stderr, "basalt: the passkey belongs to %s, not %s; delete it by hand in your password manager, or run with --pages-url %s for a forget link\n",
			removed.Origin, base, removed.Origin)
		return nil
	}
	req := passkey.ForgetRequest{
		Mode:     passkey.ModeForget,
		Removed:  []passkey.Removed{{CredentialID: removed.ID, Label: removed.Label, UserHandle: removed.UserHandle}},
		Accepted: []passkey.Bytes{},
	}
	for _, k := range keys {
		if k.RPID == removed.RPID && !equalID(k.ID, removed.ID) {
			req.Accepted = append(req.Accepted, k.ID)
		}
	}
	link, err := req.URL(base)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stderr, "basalt: removing it here does not delete it from your devices. Open this link on each device that holds it, so its password manager can forget it (browsers without the WebAuthn Signal API: delete it by hand):")
	stop := servePagesFor(c, base)
	defer stop()
	ref := linkRef{setting: "the passkey's registered origin", item: "forgetting passkey " + printableLabel(removed.Label), again: "basalt passkey remove"}
	return showLink(c, link, f.open, c.stdout, ref)
}

// showLink prints link to w, or with open opens it (printed to w when no
// browser opens).
func showLink(c *cliIO, link string, open bool, w io.Writer, ref linkRef) error {
	if open {
		return openLink(c, link, w, ref)
	}
	return printLink(c, w, link, ref)
}

// servePagesFor serves the embedded pages on a local base while a command
// waits, when nothing answers there yet (the engine not running), as
// basalt init does for registration. The hosted console needs nothing.
func servePagesFor(c *cliIO, base string) (stop func()) {
	if base == links.HostedConsole || c.host.PagesUp(c.ctx, base) {
		return func() {}
	}
	stop, served := serveLocalPages(base, nil)
	if !served {
		fmt.Fprint(c.stderr, serveHint(base))
	}
	return stop
}

func equalID(a, b []byte) bool { return passkey.Bytes(a).String() == passkey.Bytes(b).String() }

// passkeyCheck: which registered passkeys this device can still produce.
// The page signs a harmless challenge with each; the CLI verifies what it
// returns and offers to remove the ones not found.
func passkeyCheck(c *cliIO, args []string) int {
	fs, af := addAgentFlags(c, "passkey check")
	var pagesURL string
	pagesURLFlag(fs, &pagesURL, "pages base URL of the check link (default: the engine config's pagesUrl, else "+links.DefaultLocal+")")
	open := fs.Bool("open", false, "open the check link in the default browser instead of printing it")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	l, err := openLedger(c, *af.agent, *af.credFile, *af.configPath)
	if err != nil {
		return c.fail(err)
	}
	defer l.close()
	base := strings.TrimSuffix(l.pagesBase(c, pagesURL), "/")
	keys, err := l.ListPasskeys(c.ctx)
	if err != nil {
		return c.fail(err)
	}
	if len(keys) == 0 {
		return c.fail(errors.New("no active passkey; register one with basalt init --add-passkey"))
	}
	here := onBase(c, keys, base)
	if len(here) == 0 {
		return c.fail(fmt.Errorf("no active passkey is registered on %s; pass the --pages-url named above", base))
	}
	missing, err := checkOnBase(c, here, base, *open)
	if err != nil {
		return c.fail(err)
	}
	if err := offerRemoval(c, missing); err != nil {
		return c.fail(err)
	}
	return exitOK
}

// onBase is the passkeys registered on base: a page can only ask for
// passkeys of its own origin. The others are named with the --pages-url
// that checks them.
func onBase(c *cliIO, keys []ledger.Passkey, base string) []ledger.Passkey {
	var here []ledger.Passkey
	for _, k := range keys {
		if k.Credential.Relying.Origin == base {
			here = append(here, k)
			continue
		}
		fmt.Fprintf(c.stderr, "basalt: passkey %q is registered on %s; check it with --pages-url %s\n",
			k.Label, k.Credential.Relying.Origin, k.Credential.Relying.Origin)
	}
	return here
}

// checkOnBase prints (or opens) the check link for the passkeys on base,
// reads the page's code, prints each passkey's result and returns those
// not found.
func checkOnBase(c *cliIO, keys []ledger.Passkey, base string, open bool) ([]ledger.Passkey, error) {
	labeled := make([]passkey.Labeled, 0, len(keys))
	creds := make([]passkey.Credential, 0, len(keys))
	for _, k := range keys {
		labeled = append(labeled, passkey.Labeled{CredentialID: k.Credential.ID, Label: k.Label})
		creds = append(creds, k.Credential)
	}
	req, err := passkey.NewCheckRequest(c.rand, labeled)
	if err != nil {
		return nil, err
	}
	link, err := req.URL(base)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(c.stderr, "basalt: open this link on the device to check (%d passkeys for %s). It asks each passkey to sign a check that authorizes nothing:\n",
		len(keys), keys[0].Credential.Relying.RPID)
	stop := servePagesFor(c, base)
	defer stop()
	ref := linkRef{setting: "pagesUrl", item: "the passkey check", again: "basalt passkey check"}
	if err := showLink(c, link, open, c.stderr, ref); err != nil {
		return nil, err
	}
	fmt.Fprint(c.stderr, "Paste the code the page showed: ")
	code, err := c.pasted(c.ctx)
	if err != nil || code == "" {
		return nil, errors.New("no check code given")
	}
	resp, err := passkey.ParseCheckResponse(code)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUsage, err)
	}
	found, err := passkey.VerifyCheck(req, resp, creds)
	if err != nil {
		return nil, fmt.Errorf("the check code does not verify: %w", err)
	}
	var missing []ledger.Passkey
	for _, k := range keys {
		state := "found on this device"
		if !found[passkey.Bytes(k.Credential.ID).String()] {
			state = "not found on this device"
			missing = append(missing, k)
		}
		fmt.Fprintf(c.stdout, "%s  %-20s %s\n", passkey.Bytes(k.Credential.ID).String(), k.Label, state)
	}
	return missing, nil
}

// offerRemoval asks, for each passkey not found, whether to remove it, and
// removes the confirmed ones with the admin connection (asked once).
func offerRemoval(c *cliIO, missing []ledger.Passkey) error {
	var conn *pgx.Conn
	defer func() {
		if conn != nil {
			conn.Close(c.ctx)
		}
	}()
	for _, m := range missing {
		idText := passkey.Bytes(m.Credential.ID).String()
		ok, err := c.confirm(fmt.Sprintf("Remove %s (%s)? Another device may still hold it.", m.Label, idText))
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if conn == nil {
			if conn, err = connectAdmin(c); err != nil {
				return err
			}
		}
		if err := removeChecked(c, conn, idText); err != nil {
			return err
		}
	}
	return nil
}

// removeChecked runs the remove steps for a passkey the check did not
// find; the person already confirmed. The last passkey is left to
// basalt passkey remove --force.
func removeChecked(c *cliIO, conn *pgx.Conn, idText string) error {
	keys, err := guard.ActivePasskeys(c.ctx, conn)
	if err != nil {
		return err
	}
	k, err := findPasskey(keys, idText)
	if err != nil {
		return err
	}
	if len(keys) == 1 {
		fmt.Fprintf(c.stderr, "basalt: %q is the last active passkey and was kept; remove it with basalt passkey remove --force %s\n", k.Label, idText)
		return nil
	}
	return removePasskey(c, conn, keys, k, removeFlags{yes: true})
}
