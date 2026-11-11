package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// registerPath is the registration page on the relying party's origin.
const registerPath = "/register/"

// approvePath is the approval page on the same origin.
const approvePath = "/approve/"

// maxPasskeyLabel is the registration request's label limit in bytes.
const maxPasskeyLabel = 64

// relyingParty is basaltvault.app, or the local development page when
// origin is set (http://localhost:<port>).
func relyingParty(origin string) (passkey.Relying, error) {
	if origin == "" {
		return passkey.Production, nil
	}
	rp, err := passkey.Local(origin)
	if err != nil {
		return passkey.Relying{}, fmt.Errorf("%w: --passkey-origin: %w", errUsage, err)
	}
	return rp, nil
}

// webMarker is a file only the repo's web/ directory has.
const webMarker = "web/register/index.html"

// findWebDir walks up from dir to the nearest directory holding the
// approval pages (a BasaltDB checkout) and returns its web/, or "".
func findWebDir(dir string) string {
	for dir != "" {
		if _, err := os.Stat(filepath.Join(dir, webMarker)); err == nil {
			return filepath.Join(dir, "web")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// workingDir is the current directory, or "" when it cannot be read.
func workingDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	return dir
}

// serveHint tells the person how to serve the development pages on origin
// (http://localhost:<port>): the exact command when a BasaltDB checkout is
// found from dir, else where to run it. A page server started anywhere
// else answers the link with 404.
func serveHint(origin, dir string) string {
	port := origin[strings.LastIndex(origin, ":")+1:]
	if web := findWebDir(dir); web != "" {
		return fmt.Sprintf("  (the page must be served first; in another terminal: python3 -m http.server %s --bind 127.0.0.1 --directory %s)\n",
			port, shellQuote(web))
	}
	return fmt.Sprintf("  (the page must be served first: in the BasaltDB repo run make serve-web PORT=%s; a 404 means the server is not serving the repo's web/)\n", port)
}

// hasPasskey reports whether a passkey is registered for this database.
func hasPasskey(c *cliIO, conn *pgx.Conn) (bool, error) {
	var ok bool
	// Plain SQL: a presence check on the admin connection.
	err := conn.QueryRow(c.ctx, `SELECT EXISTS (SELECT 1 FROM basalt_meta.passkeys)`).Scan(&ok)
	return ok, err
}

// registerPasskey is basalt init's passkey step: print the registration
// link, read the code the page shows, verify it, and store the public key
// with the admin connection (owner decision #3; CONTRACT.md, Approvals).
func registerPasskey(c *cliIO, conn *pgx.Conn, rp passkey.Relying, label string) error {
	db := conn.Config().Database
	display := "BasaltDB · " + db
	if len(display) > maxPasskeyLabel {
		display = label
	}
	req, err := passkey.NewRegistrationRequest(c.rand, label, display)
	if err != nil {
		return err
	}
	frag, err := req.Fragment()
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: register the passkey that approves this agent's held writes. Open this link on your phone or computer:\n  %s%s#%s\n",
		rp.Origin, registerPath, frag)
	if rp != passkey.Production {
		fmt.Fprint(c.stderr, serveHint(rp.Origin, workingDir()))
	}
	fmt.Fprint(c.stderr, "Paste the code the page shows: ")
	code, err := c.line()
	if err != nil {
		return fmt.Errorf("no passkey code: %w", err)
	}
	if strings.TrimSpace(code) == "" {
		return errors.New("no passkey code given")
	}
	resp, err := passkey.ParseRegistrationResponse(code)
	if err != nil {
		return err
	}
	cred, err := passkey.VerifyRegistration(req, resp, rp)
	if err != nil {
		return err
	}
	return guard.RegisterPasskey(c.ctx, conn, cred, label)
}

// passkeyStep registers the person's passkey unless one is registered
// already (--add-passkey registers another) or --skip-passkey.
func passkeyStep(c *cliIO, conn *pgx.Conn, f initFlags) error {
	if f.skipPasskey {
		fmt.Fprintln(c.stderr, "basalt: no passkey registered (--skip-passkey); held writes cannot be approved until you run basalt init again without it")
		return nil
	}
	has, err := hasPasskey(c, conn)
	if err != nil {
		return err
	}
	if has && !f.addPasskey {
		return nil
	}
	rp, err := relyingParty(f.passkeyOrigin)
	if err != nil {
		return err
	}
	label := f.passkeyLabel
	if label == "" {
		label = conn.Config().Database
	}
	if err := registerPasskey(c, conn, rp, label); err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "basalt: passkey registered for %s\n", rp.RPID)
	return nil
}
