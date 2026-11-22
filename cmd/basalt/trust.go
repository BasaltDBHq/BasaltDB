package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// trustUsage names basalt trust's subcommands.
const trustUsage = "basalt trust list | add --name N --match SUFFIX[,...] --ca FILE | pin --host H [--port P] | remove --name N | disable --name N"

// runTrust is basalt trust (CONTRACT.md, CLI, basalt trust).
func runTrust(c *cliIO, args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("%w: %s", errUsage, trustUsage))
	}
	switch args[0] {
	case "list":
		return trustList(c, args[1:])
	case "add":
		return trustAdd(c, args[1:])
	case "pin":
		return trustPin(c, args[1:])
	case "remove":
		return trustRemove(c, args[1:])
	case "disable":
		return trustDisable(c, args[1:])
	}
	return c.fail(fmt.Errorf("%w: unknown trust command %q (%s)", errUsage, args[0], trustUsage))
}

// trustRoot is one root of a listed profile.
type trustRoot struct {
	File     string    `json:"file"`
	Subject  string    `json:"subject"`
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"notAfter"`
}

// trustProfileView is one profile basalt trust list shows.
type trustProfileView struct {
	Name   string      `json:"name"`
	Origin string      `json:"origin"`
	State  string      `json:"state"`
	Match  []string    `json:"match,omitempty"`
	Verify string      `json:"verify,omitempty"`
	Roots  []trustRoot `json:"roots,omitempty"`
}

// trustAgentView is which roots verify one agent's database host.
type trustAgentView struct {
	Agent   string `json:"agent"`
	Host    string `json:"host,omitempty"`
	Applies string `json:"applies,omitempty"`
	Profile string `json:"profile,omitempty"`
	// Unknown says why the host is not known (the credential cannot be
	// read as this user, or there is none yet).
	Unknown string `json:"unknown,omitempty"`
}

// trustListView is basalt trust list --json.
type trustListView struct {
	TrustDir string                 `json:"trustDir"`
	Profiles []trustProfileView     `json:"profiles"`
	Refused  []trustprofile.Refused `json:"refused"`
	Agents   []trustAgentView       `json:"agents"`
}

func trustRoots(p *trustprofile.Profile) []trustRoot {
	var out []trustRoot
	for _, f := range p.Files {
		for _, cert := range f.Certs {
			out = append(out, trustRoot{File: f.Name, Subject: cert.Subject.String(), SHA256: trustprofile.Fingerprint(cert), NotAfter: cert.NotAfter.UTC()})
		}
	}
	return out
}

func trustList(c *cliIO, args []string) int {
	fs := c.flags("trust list")
	asJSON := fs.Bool("json", false, "print the list as JSON")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	configPath, err := c.findConfig()
	if err != nil {
		return c.fail(err)
	}
	set := trustdir.Set(configPath)
	v := trustListView{TrustDir: trustdir.Path(configPath), Refused: set.Refused(), Agents: trustAgents(c, configPath)}
	for _, l := range set.Profiles() {
		v.Profiles = append(v.Profiles, trustProfileView{
			Name: l.Name, Origin: string(l.Origin), State: string(l.State), Match: l.Match, Verify: l.Verify, Roots: trustRoots(l.Profile),
		})
	}
	if v.Refused == nil {
		v.Refused = []trustprofile.Refused{}
	}
	if *asJSON {
		return printJSONValue(c, v)
	}
	printTrustList(c.stdout, v)
	return exitOK
}

// trustAgents is, for each agent of the config, which roots verify its
// database host, from its credential when this user can read it.
func trustAgents(c *cliIO, configPath string) []trustAgentView {
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return []trustAgentView{}
	}
	out := make([]trustAgentView, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		v := trustAgentView{Agent: a.Name}
		dsn, err := cfg.credential(a.Store.CredentialFile)
		if err != nil {
			v.Unknown = "the agent's credential cannot be read as this user"
			out = append(out, v)
			continue
		}
		applied, _, err := pgdial.TrustOf(dsn)
		if err != nil {
			v.Unknown = "the agent's credential is not a valid connection string"
			out = append(out, v)
			continue
		}
		v.Host, v.Applies = applied.Host, string(applied.Applies)
		if applied.Profile != nil {
			v.Profile = applied.Profile.Name
		}
		out = append(out, v)
	}
	return out
}

func printTrustList(w io.Writer, v trustListView) {
	for _, p := range v.Profiles {
		line := fmt.Sprintf("%s  %s  %s", p.Name, strings.ToLower(strings.ReplaceAll(p.Origin, "_", "-")), strings.ToLower(p.State))
		if len(p.Match) > 0 {
			line += "  match " + strings.Join(p.Match, ", ")
		}
		fmt.Fprintln(w, terminalText(line))
		if len(p.Roots) > maxRootsShown {
			fmt.Fprintf(w, "  %d roots, the first to expire on %s (basalt trust list --json lists each)\n", len(p.Roots), firstExpiry(p.Roots).Format(time.DateOnly))
			continue
		}
		for _, r := range p.Roots {
			fmt.Fprintln(w, terminalText(fmt.Sprintf("  %s  SHA-256 %s  expires %s", r.Subject, r.SHA256, r.NotAfter.Format(time.DateOnly))))
		}
	}
	for _, r := range v.Refused {
		fmt.Fprintln(w, terminalText("refused  "+r.File+": "+r.Reason))
	}
	for _, a := range v.Agents {
		switch {
		case a.Unknown != "":
			fmt.Fprintln(w, terminalText(fmt.Sprintf("agent %s: %s", a.Agent, a.Unknown)))
		case a.Profile != "":
			fmt.Fprintln(w, terminalText(fmt.Sprintf("agent %s: %s is verified with profile %s and the system's authorities", a.Agent, a.Host, a.Profile)))
		default:
			fmt.Fprintln(w, terminalText(fmt.Sprintf("agent %s: %s: %s", a.Agent, a.Host, appliesWords(a.Applies))))
		}
	}
}

// maxRootsShown is how many roots of a profile basalt trust list prints
// one by one; a bundle (AWS's, 114 roots) is summed up.
const maxRootsShown = 4

func firstExpiry(roots []trustRoot) time.Time {
	first := roots[0].NotAfter
	for _, r := range roots[1:] {
		if r.NotAfter.Before(first) {
			first = r.NotAfter
		}
	}
	return first
}

// appliesWords says what verifies a host that no profile matches.
func appliesWords(applies string) string {
	switch trustprofile.Applies(applies) {
	case trustprofile.AppliesRootCert:
		return "verified with the sslrootcert its connection string names"
	case trustprofile.AppliesNotVerified:
		return "its sslmode does not verify the host name, so no profile applies"
	case trustprofile.AppliesProfile, trustprofile.AppliesSystem:
	}
	return "verified with the system's authorities alone"
}

func trustAdd(c *cliIO, args []string) int {
	fs := c.flags("trust add")
	name := fs.String("name", "", "the profile's name: lowercase letters, digits and dashes (a built-in's name replaces it)")
	match := fs.String("match", "", "the hosts it applies to, comma-separated: a domain (its hosts below it) or =host (one host)")
	caFile := fs.String("ca", "", "PEM file of the certificate authority (or authorities) that signs the database's certificate")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	configPath, err := c.findConfig()
	if err != nil {
		return c.fail(err)
	}
	if *name == "" || *match == "" || *caFile == "" {
		return c.fail(fmt.Errorf("%w: --name, --match and --ca are required: %s", errUsage, trustUsage))
	}
	if err := c.refuseAgentTrust("add", configPath); err != nil {
		return c.fail(err)
	}
	ca, err := readCAFile(*caFile)
	if err != nil {
		return c.fail(fmt.Errorf("%w: --ca: %w", errUsage, err))
	}
	p, err := trustdir.Add(configPath, *name, splitList(*match), ca)
	if err != nil {
		return c.fail(trustWriteError(c, "add", err))
	}
	fmt.Fprintf(c.stdout, "basalt: added trust profile %s for %s in %s\n", p.Name, strings.Join(p.Match, ", "), trustdir.Path(configPath))
	printRoots(c.stdout, p.Certificates())
	if b := trustprofile.BuiltInSet().Named(p.Name); b != nil {
		fmt.Fprintf(c.stdout, "basalt: it replaces the built-in profile %s\n", p.Name)
	}
	fmt.Fprintln(c.stderr, "basalt: the engine uses it from its next connection; no restart is needed")
	return exitOK
}

func printRoots(w io.Writer, certs []*x509.Certificate) {
	for _, cert := range certs {
		fmt.Fprintln(w, terminalText(fmt.Sprintf("  %s  SHA-256 %s  expires %s", cert.Subject, trustprofile.Fingerprint(cert), cert.NotAfter.UTC().Format(time.DateOnly))))
	}
}

// readCAFile is the PEM file at path, refused when it is too large.
func readCAFile(path string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, trustprofile.MaxRootFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > trustprofile.MaxRootFileBytes {
		return nil, fmt.Errorf("%s is over %d bytes", path, trustprofile.MaxRootFileBytes)
	}
	return b, nil
}

func trustRemove(c *cliIO, args []string) int {
	fs := c.flags("trust remove")
	name := fs.String("name", "", "the operator profile to remove (a disabled built-in applies again)")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	configPath, err := c.findConfig()
	if err != nil {
		return c.fail(err)
	}
	if *name == "" {
		return c.fail(fmt.Errorf("%w: --name is required: basalt trust remove --name N", errUsage))
	}
	// Removing a profile that disables or narrows a built-in brings the
	// built-in's roots back, so an agent never removes one either.
	if err := c.refuseAgentTrust("remove", configPath); err != nil {
		return c.fail(err)
	}
	if err := trustdir.Remove(configPath, *name); err != nil {
		if errors.Is(err, trustdir.ErrNotFound) && trustprofile.BuiltInSet().Named(*name) != nil {
			err = fmt.Errorf("%s is a built-in profile, which cannot be removed; turn it off with basalt trust disable --name %s", *name, *name)
		}
		return c.fail(trustWriteError(c, "remove", err))
	}
	fmt.Fprintf(c.stdout, "basalt: removed trust profile %s from %s\n", *name, trustdir.Path(configPath))
	if trustprofile.BuiltInSet().Named(*name) != nil {
		fmt.Fprintf(c.stdout, "basalt: the built-in profile %s applies again\n", *name)
	}
	return exitOK
}

func trustDisable(c *cliIO, args []string) int {
	fs := c.flags("trust disable")
	name := fs.String("name", "", "the built-in profile to turn off")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	configPath, err := c.findConfig()
	if err != nil {
		return c.fail(err)
	}
	if *name == "" {
		return c.fail(fmt.Errorf("%w: --name is required: basalt trust disable --name N", errUsage))
	}
	if trustprofile.BuiltInSet().Named(*name) == nil {
		return c.fail(fmt.Errorf("%w: %q is not a built-in profile (basalt trust list shows them); remove an operator profile with basalt trust remove", errUsage, *name))
	}
	if err := trustdir.Disable(configPath, *name); err != nil {
		if errors.Is(err, trustdir.ErrExists) {
			err = fmt.Errorf("trust.d already holds a profile named %s (it replaces or disables the built-in); remove it first with basalt trust remove --name %s", *name, *name)
		}
		return c.fail(trustWriteError(c, "disable", err))
	}
	fmt.Fprintf(c.stdout, "basalt: the built-in profile %s is off; basalt trust remove --name %s turns it on again\n", *name, *name)
	return exitOK
}

// refuseAgentTrust refuses basalt trust sub when an agent marker is set or
// the engine is operatedBy AGENT: an agent never adds a root, and never
// removes a profile (which can bring a built-in's roots back). An
// engine.json that exists and cannot be read is refused too.
func (c *cliIO) refuseAgentTrust(sub, configPath string) error {
	if marker := c.agentMarker(); marker != "" {
		return fmt.Errorf("trust %s is refused: %s is set, so an agent is running it, and an agent never changes which root certificates "+
			"are trusted. Nothing was written. The person runs it in a terminal of their own", sub, marker)
	}
	cfg, err := loadEngineConfig(c, configPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("trust %s is refused: %s cannot be read (%w), so whether an agent operates this engine is not known. Nothing was written", sub, configPath, err)
	case cfg.AgentOperated():
		return fmt.Errorf("trust %s is refused: this engine is operatedBy AGENT, so an agent could have run it, and an agent never changes which "+
			"root certificates are trusted. Nothing was written. Name the root in the agent's connection string with sslrootcert instead", sub)
	}
	return nil
}

// trustWriteError adds to err the hint for a trust.d the user cannot write.
func trustWriteError(c *cliIO, sub string, err error) error {
	if errors.Is(err, fs.ErrPermission) && c.host.Euid() != 0 {
		return fmt.Errorf("%w; trust.d belongs to the engine's user: run basalt trust %s with sudo", err, sub)
	}
	return err
}
