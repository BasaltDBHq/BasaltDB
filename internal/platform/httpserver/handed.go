package httpserver

import (
	"net"
	"time"
)

// TakeHandedListener is the listener a waiting engine handed on, when the
// config serves its pages at that same address (want, the address the
// waiting engine served on); else it is closed and the pages bind as usual.
func TakeHandedListener(ln net.Listener, addr, want string) net.Listener {
	if ln == nil {
		return nil
	}
	if addr == want && ln.Addr().String() == addr {
		return ln
	}
	_ = ln.Close()
	return nil
}

// Deadliner is a listener whose Accept a deadline can wake (a TCP
// listener).
type Deadliner interface {
	SetDeadline(t time.Time) error
}

// KeptListener is what the setup page serves on: closing it, as
// http.Server.Shutdown does, only wakes its Accept with a deadline, so the
// socket stays bound for the engine that takes it over.
type KeptListener struct {
	net.Listener
	Keep Deadliner
}

func (k KeptListener) Close() error { return k.Keep.SetDeadline(time.Now()) }
