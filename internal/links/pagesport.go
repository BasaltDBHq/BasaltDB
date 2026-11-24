package links

import (
	"fmt"
	"net"
	"time"
)

// PagesHeaderTimeout bounds a page request's headers (slowloris).
const PagesHeaderTimeout = 10 * time.Second

// PagesPortError is err, from binding the approval pages at addr, with what
// to do about it.
func PagesPortError(addr string, err error) error {
	port := addr
	if _, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		port = p
	}
	return fmt.Errorf("%w: another process holds %s (an old `make serve-web`, or another engine): "+
		"find it with `lsof -nP -iTCP:%s -sTCP:LISTEN`, stop it and start the engine again "+
		`(or set "pagesAddr": "off" in engine.json to run without the pages)`, err, addr, port)
}
