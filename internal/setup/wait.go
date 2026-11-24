package setup

import (
	"fmt"
	"net"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// PageOrigin is the setup page's origin.
const PageOrigin = links.DefaultLocal

// PageAddr is where an engine with no config serves its setup page: the
// default local pages address (origin http://localhost:8787).
const PageAddr = "127.0.0.1:8787"

// ConfigPollInterval is how often an engine with no config looks for it.
const ConfigPollInterval = time.Second

// PortError is err, from binding the setup page at addr, with what to do
// about it.
func PortError(addr string, err error) error {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	return fmt.Errorf("%w: the engine has no config yet and serves its setup page on %s, but another process holds it: "+
		"find it with `lsof -nP -iTCP:%s -sTCP:LISTEN`, stop it and start the engine again", err, addr, port)
}
