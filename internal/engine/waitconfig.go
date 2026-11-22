package engine

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

	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

// WaitOptions are where and how an engine with no config serves its setup
// page.
type WaitOptions struct {
	// Addr is the listener's address (SetupAddr) and Origin the page
	// origin a setup POST must carry (SetupOrigin).
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

// SetupOrigin is the setup page's origin.
const SetupOrigin = links.DefaultLocal

// SetupAddr is where an engine with no config serves its setup page: the
// default local pages address (origin http://localhost:8787).
const SetupAddr = "127.0.0.1:8787"

// configPollInterval is how often an engine with no config looks for it.
const configPollInterval = time.Second

// WaitForConfig is an engine with no config (CONTRACT.md, The local setup
// page): it serves only GET /healthz and the setup routes on addr until
// configPath exists, then stops serving and returns the listener, still
// bound, for the engine's own pages (RestartOptions.PagesListener): the
// port is never free for another process between the two. A taken port is
// an error naming it; so is a config path that cannot be looked at. On any
// error the listener is closed.
func WaitForConfig(ctx context.Context, o WaitOptions) (net.Listener, error) {
	addr, configPath, log := o.Addr, o.ConfigPath, o.Log
	jobs, err := localsetup.New(localsetup.Options{ConfigPath: configPath, Origin: o.Origin, Dial: o.Dial, Users: o.Users, Prefix: o.Prefix})
	if err != nil {
		return nil, err
	}
	ln, h, err := server.Listen(server.Options{}, "setup page", addr, pages.SetupOnlyHandler(o.Origin, jobs, log.With("component", "setup")))
	if err != nil {
		return nil, setupPortError(addr, err)
	}
	keep, ok := ln.(deadliner)
	if !ok {
		_ = ln.Close()
		return nil, errors.New("the setup page's listener cannot be handed on")
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: pagesHeaderTimeout}
	served := make(chan error, 1)
	go func() {
		served <- hs.Serve(keptListener{Listener: ln, keep: keep})
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
	t := time.NewTicker(configPollInterval)
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

// deadliner is a listener whose Accept a deadline can wake (a TCP
// listener).
type deadliner interface {
	SetDeadline(t time.Time) error
}

// keptListener is what the setup page serves on: closing it, as
// http.Server.Shutdown does, only wakes its Accept with a deadline, so the
// socket stays bound for the engine that takes it over.
type keptListener struct {
	net.Listener
	keep deadliner
}

func (k keptListener) Close() error { return k.keep.SetDeadline(time.Now()) }

func setupPortError(addr string, err error) error {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	return fmt.Errorf("%w: the engine has no config yet and serves its setup page on %s, but another process holds it: "+
		"find it with `lsof -nP -iTCP:%s -sTCP:LISTEN`, stop it and start the engine again", err, addr, port)
}
