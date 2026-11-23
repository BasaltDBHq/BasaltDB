package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/httpserver"
	"github.com/basaltdbhq/basaltdb/internal/setup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/setup/in/setuppage"
)

// WaitOptions are where and how an engine with no config serves its setup
// page.
type WaitOptions struct {
	// Addr is the listener's address (setup.PageAddr) and Origin the page
	// origin a setup POST must carry (setup.PageOrigin).
	Addr, Origin string
	// ConfigPath is the engine.json it waits for, and the setup writes.
	ConfigPath string
	Log        *slog.Logger
	// Dial, Users and Prefix replace the setup's defaults (tests only:
	// localsetup.Options).
	Dial   func(ctx context.Context, dsn string) (*pgx.Conn, error)
	Users  localsetup.Users
	Prefix string
}

// WaitForConfig is an engine with no config (CONTRACT.md, The local setup
// page): it serves only GET /healthz and the setup routes on addr until
// configPath exists, then stops serving and returns the listener, still
// bound, for the engine's own pages (RestartOptions.PagesListener): the
// port is never free for another process between the two. A taken port is
// an error naming it; so is a config path that cannot be looked at. On any
// error the listener is closed.
func WaitForConfig(ctx context.Context, o WaitOptions) (net.Listener, error) {
	addr, configPath, log := o.Addr, o.ConfigPath, o.Log
	jobs, err := newLocalSetup(localsetup.Options{ConfigPath: configPath, Origin: o.Origin, Dial: o.Dial, Users: o.Users, Prefix: o.Prefix})
	if err != nil {
		return nil, err
	}
	ln, h, err := httpserver.Listen(httpserver.Options{}, "setup page", addr, setuppage.SetupOnlyHandler(o.Origin, jobs, log.With("component", "setup")))
	if err != nil {
		return nil, setup.PortError(addr, err)
	}
	keep, ok := ln.(httpserver.Deadliner)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("the setup page's listener cannot be handed on")
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: linksvc.PagesHeaderTimeout}
	served := make(chan error, 1)
	go func() {
		served <- hs.Serve(httpserver.KeptListener{Listener: ln, Keep: keep})
		close(served)
	}()
	// stop ends the setup page's serving and waits for it, leaving ln bound.
	stop := func() {
		_ = hs.Shutdown(context.WithoutCancel(ctx))
		for range served {
		}
		_ = keep.SetDeadline(time.Time{})
	}
	log.Info("no engine config yet: serving only the setup page until it exists", "config", configPath, "addr", ln.Addr().String())
	t := time.NewTicker(setup.ConfigPollInterval)
	defer t.Stop()
	for {
		switch _, err := os.Lstat(configPath); {
		case err == nil:
			stop()
			log.Info("engine config found: starting the engine", "config", configPath)
			return ln, nil
		case !errors.Is(err, fs.ErrNotExist):
			stop()
			_ = ln.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			stop()
			_ = ln.Close()
			return nil, ctx.Err()
		case err := <-served:
			_ = ln.Close()
			return nil, fmt.Errorf("the setup page stopped: %w", err)
		case <-t.C:
		}
	}
}
