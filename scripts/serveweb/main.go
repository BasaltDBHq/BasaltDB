// Command serveweb serves the working tree's web/ at the pages' paths
// (/approvals/<id>, /reverts/<id>, /passkeys/register) on loopback, for
// page development (make serve-web). It holds no agent, so short links
// answer 404; long links (with the request in the fragment) work. The
// engine and basalt init serve the built-in pages themselves.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/pages"
	"github.com/basaltdbhq/basaltdb/internal/server"
)

// headerTimeout bounds a request's headers.
const headerTimeout = 10 * time.Second

func main() {
	port := flag.String("port", "8787", "port on 127.0.0.1; the page origin is http://localhost:<port>")
	dir := flag.String("dir", "web", "the pages' directory")
	flag.Parse()
	if err := run(*port, *dir); err != nil {
		fmt.Fprintln(os.Stderr, "serveweb:", err)
		os.Exit(1)
	}
}

func run(port, dir string) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	site := pages.NewWithFiles("http://localhost:"+port, log, os.DirFS(dir))
	ln, h, err := server.Listen(server.Options{}, "dev pages", "127.0.0.1:"+port, site.Handler())
	if err != nil {
		return err
	}
	log.Info("serving the working tree's pages", "dir", dir, "origin", "http://localhost:"+port)
	hs := &http.Server{Handler: h, ReadHeaderTimeout: headerTimeout}
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
