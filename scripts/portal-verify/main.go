// Command portal-verify compares the files the hosted portal serves with
// the pages embedded in this build, and with a release's "sha256  path"
// manifest when one is given (CONTRACT.md, CLI, Portal check). The release
// workflow runs it; run it by hand with make portal-verify. Read-only: no
// Postgres, no engine.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/status"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:]))
}

func run(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("portal-verify", flag.ContinueOnError)
	rawURL := fs.String("portal-url", links.Portal, "portal origin to check: an https URL, or an http URL on a loopback host (for tests)")
	manifestPath := fs.String("manifest", "", "also check the embedded pages against this \"sha256  path\" manifest (for example web/portal.sha256)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	base, err := status.ValidateURL(*rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portal-verify: --portal-url: %v\n", err)
		return 2
	}
	opts := app.PortalcheckOptions(base)
	if *manifestPath != "" {
		b, err := os.ReadFile(filepath.Clean(*manifestPath))
		if err == nil {
			_, err = status.ParseManifest(b)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "portal-verify: --manifest: %v\n", err)
			return 2
		}
		opts.Manifest, opts.ManifestSource = b, *manifestPath
	}
	report, err := status.Verify(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "portal-verify: %v\n", err)
		return 1
	}
	printReport(report)
	if !report.OK {
		return 1
	}
	return 0
}

// clean shows a control character the portal sent as an escape, never raw.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

func printReport(report *status.Report) {
	problems := 0
	for _, f := range report.Files {
		line := fmt.Sprintf("%-10s %s", f.Status, f.Path)
		if f.Detail != "" {
			line += "  (" + f.Detail + ")"
		}
		fmt.Println(clean(line))
		if f.Status != status.StatusOK {
			problems++
		}
	}
	if m := report.Manifest; m != nil {
		fmt.Printf("%-10s release manifest (%s)\n", m.Status, clean(m.Source))
		for _, d := range m.Mismatches {
			fmt.Printf("           %s\n", clean(d))
		}
		if m.Status != status.StatusOK {
			problems++
		}
	}
	if report.OK {
		fmt.Printf("portal-verify: %s serves the %d files embedded in this build and its page routes\n", report.PortalURL, report.Checked)
	} else {
		fmt.Printf("portal-verify: %s does not match this build: %d problem(s) in %d embedded files\n", report.PortalURL, problems, report.Checked)
	}
}
