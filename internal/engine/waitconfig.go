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

	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

// SetupAddr is where an engine with no config serves its setup page: the
// default local pages address (origin http://localhost:8787).
const SetupAddr = "127.0.0.1:8787"

// configPollInterval is how often an engine with no config looks for it.
const configPollInterval = time.Second

// WaitForConfig is an engine with no config (CONTRACT.md, The local setup
// page): it serves only GET /healthz and the setup routes on addr until
// configPath exists, then stops serving and returns nil, so the caller
// loads the config and runs the engine in this process. A taken port is
// an error naming it; so is a config path that cannot be looked at.
func WaitForConfig(ctx context.Context, addr, configPath string, log *slog.Logger) error {
	ln, h, err := server.Listen(server.Options{}, "setup page", addr, pages.SetupOnlyHandler())
	if err != nil {
		return setupPortError(addr, err)
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: pagesHeaderTimeout}
	served := make(chan error, 1)
	go func() {
		served <- hs.Serve(ln)
		close(served)
	}()
	defer func() {
		_ = hs.Shutdown(context.WithoutCancel(ctx))
		// Wait until it stopped serving (http.ErrServerClosed), so the port
		// is free for the engine's own pages.
		for range served {
		}
	}()
	log.Info("no engine config yet: serving only the setup page until it exists", "config", configPath, "addr", ln.Addr().String())
	t := time.NewTicker(configPollInterval)
	defer t.Stop()
	for {
		switch _, err := os.Lstat(configPath); {
		case err == nil:
			log.Info("engine config found: starting the engine", "config", configPath)
			return nil
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-served:
			return fmt.Errorf("the setup page stopped: %w", err)
		case <-t.C:
		}
	}
}

func setupPortError(addr string, err error) error {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	return fmt.Errorf("%w: the engine has no config yet and serves its setup page on %s, but another process holds it: "+
		"find it with `lsof -nP -iTCP:%s -sTCP:LISTEN`, stop it and start the engine again", err, addr, port)
}
