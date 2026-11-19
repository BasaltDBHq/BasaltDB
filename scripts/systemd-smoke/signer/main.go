// Command signer is the person's passkey in scripts/systemd-smoke/smoke.sh:
// a software passkey (passkeytest) the smoke test registers in the demo
// database and signs a plugin approval with, as a person does on the plugin
// approval page.
//
//	signer -key FILE register   make the passkey, keep it in FILE (0600) and
//	                            register it with BASALT_ADMIN_DATABASE_URL
//	signer -key FILE code URL   read the approval behind URL (a short link
//	                            on the engine's local pages, or a long link),
//	                            check it, sign it and print the
//	                            basalt-plugin.1. code the page would show
//
// It is test tooling for a throwaway CI machine, never shipped.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// keyFile is what the passkey keeps between the two commands.
type keyFile struct {
	ID      []byte `json:"id"`
	Key     []byte `json:"key"`
	Counter uint32 `json:"counter"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "signer:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("signer", flag.ContinueOnError)
	path := fs.String("key", "", "the passkey's file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() == 0 {
		return errors.New("usage: signer -key FILE register | code URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	switch fs.Arg(0) {
	case "register":
		return register(ctx, *path)
	case "code":
		if fs.NArg() != 2 {
			return errors.New("usage: signer -key FILE code URL")
		}
		return code(ctx, *path, fs.Arg(1))
	}
	return fmt.Errorf("unknown command %q", fs.Arg(0))
}

func register(ctx context.Context, path string) error {
	a, err := passkeytest.New(passkey.Production)
	if err != nil {
		return err
	}
	if err := save(path, a); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, os.Getenv("BASALT_ADMIN_DATABASE_URL"))
	if err != nil {
		return fmt.Errorf("connect as the admin: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	return guard.RegisterPasskey(ctx, conn, a.Credential(), "systemd smoke")
}

func save(path string, a *passkeytest.Authenticator) error {
	der, err := x509.MarshalECPrivateKey(a.Key)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(keyFile{ID: a.ID, Key: der, Counter: a.Counter})
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func load(path string) (*passkeytest.Authenticator, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k keyFile
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(k.Key)
	if err != nil {
		return nil, err
	}
	return &passkeytest.Authenticator{ID: k.ID, Key: (*ecdsa.PrivateKey)(key), Counter: k.Counter, Relying: passkey.Production}, nil
}

// code signs the approval behind link and prints the response code.
func code(ctx context.Context, path, link string) error {
	a, err := load(path)
	if err != nil {
		return err
	}
	req, err := request(ctx, link)
	if err != nil {
		return err
	}
	if _, err := req.Check(); err != nil {
		return fmt.Errorf("the approval's texts do not check: %w", err)
	}
	as, err := a.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	if err != nil {
		return err
	}
	if err := save(path, a); err != nil {
		return err
	}
	c, err := approval.NewPluginApprovalResponse(req.ApprovalID, as).Code()
	if err != nil {
		return err
	}
	fmt.Println(c)
	return nil
}

// request is what the page reads for link: GET /api/v1/plugins/{id} with
// the short link's secret, or the long link's own fragment.
func request(ctx context.Context, link string) (approval.PluginRequest, error) {
	u, err := url.Parse(link)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	if !strings.HasPrefix(u.Fragment, "s=") {
		req, _, err := approval.ParsePluginRequest(u.Fragment)
		return req, err
	}
	id, err := uuid.Parse(strings.TrimPrefix(u.Path, "/plugins/"))
	if err != nil {
		return approval.PluginRequest{}, fmt.Errorf("not a plugin approval link: %s", u.Path)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Scheme+"://"+u.Host+"/api/v1/plugins/"+id.String(), nil)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	r.Header.Set(links.SecretHeader, strings.TrimPrefix(u.Fragment, "s="))
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return approval.PluginRequest{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return approval.PluginRequest{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return approval.PluginRequest{}, fmt.Errorf("the engine's pages answered %d: %s", resp.StatusCode, body)
	}
	var req approval.PluginRequest
	return req, json.Unmarshal(body, &req)
}
