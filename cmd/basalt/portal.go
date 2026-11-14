package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/portalverify"
	"github.com/basaltdbhq/basaltdb/internal/websec"
	"github.com/basaltdbhq/basaltdb/web"
)

// runPortal is basalt portal (verify).
func runPortal(c *cliIO, args []string) int {
	if len(args) == 0 {
		return c.fail(fmt.Errorf("%w: basalt portal verify", errUsage))
	}
	if args[0] == "verify" {
		return portalVerify(c, args[1:])
	}
	return c.fail(fmt.Errorf("%w: unknown portal command %q (verify)", errUsage, args[0]))
}

// portalVerify compares the files the hosted portal serves with the pages
// embedded in this binary. Read-only: no Postgres, no engine.
func portalVerify(c *cliIO, args []string) int {
	fs := c.flags("portal verify")
	rawURL := fs.String("portal-url", links.Portal, "portal origin to check: an https URL, or an http URL on a loopback host (for tests)")
	manifestPath := fs.String("manifest", "", "also check the embedded pages against this \"sha256  path\" manifest (for example one downloaded from the release)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	base, err := portalverify.ValidateURL(*rawURL)
	if err != nil {
		return c.fail(fmt.Errorf("%w: --portal-url: %w", errUsage, err))
	}
	opts := portalverify.Options{
		Base: base, Files: web.Files, Headers: websec.Expected(),
		Manifest: web.Manifest, ManifestSource: "embedded",
	}
	if *manifestPath != "" {
		b, rerr := os.ReadFile(filepath.Clean(*manifestPath))
		if rerr != nil {
			return c.fail(fmt.Errorf("%w: --manifest: %w", errUsage, rerr))
		}
		if _, perr := portalverify.ParseManifest(b); perr != nil {
			return c.fail(fmt.Errorf("%w: --manifest: %w", errUsage, perr))
		}
		opts.Manifest, opts.ManifestSource = b, *manifestPath
	}
	report, err := portalverify.Verify(c.ctx, opts)
	if err != nil {
		return c.fail(errors.Join(errors.New("portal verify"), err))
	}
	code := exitOK
	if !report.OK {
		code = exitError
	}
	if *asJSON {
		if rc := printJSONValue(c, report); rc != exitOK {
			return rc
		}
		return code
	}
	problems := 0
	for _, f := range report.Files {
		line := fmt.Sprintf("%-10s %s", f.Status, f.Path)
		if f.Detail != "" {
			line += "  (" + f.Detail + ")"
		}
		fmt.Fprintln(c.stdout, terminalText(line))
		if f.Status != portalverify.StatusOK {
			problems++
		}
	}
	if m := report.Manifest; m != nil {
		fmt.Fprintf(c.stdout, "%-10s release manifest (%s)\n", m.Status, terminalText(m.Source))
		for _, d := range m.Mismatches {
			fmt.Fprintf(c.stdout, "           %s\n", terminalText(d))
		}
		if m.Status != portalverify.StatusOK {
			problems++
		}
	}
	if report.OK {
		fmt.Fprintf(c.stdout, "basalt: %s serves the %d files embedded in this binary\n", report.PortalURL, report.Checked)
	} else {
		fmt.Fprintf(c.stdout, "basalt: %s does not match this binary: %d problem(s) in %d embedded files\n", report.PortalURL, problems, report.Checked)
	}
	return code
}
