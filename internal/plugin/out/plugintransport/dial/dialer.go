package dial

import (
	"context"
	"errors"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/child"
)

// Dialer is how the plugin host reaches its entries (its Dialer port): Entry
// and Service as functions, with the engine's run records.
type Dialer struct {
	// Runs, when set, records each local process started (child.Runs), so the
	// engine's next start can reap one a crash left running.
	Runs *child.Runs
}

// Entry starts or connects to the entry as the package function does.
func (d Dialer) Entry(ctx context.Context, k pluginmodel.EntryKey, v pluginmodel.Verified, socketBase, credentialFile string, stderr io.Writer) (pluginmodel.Transport, error) {
	return Entry(ctx, k, v, Options{SocketBase: socketBase, Runs: d.Runs, CredentialFile: credentialFile, Stderr: stderr})
}

// Service connects to the entry's unit on its socket.
func (Dialer) Service(ctx context.Context, k pluginmodel.EntryKey, v pluginmodel.Verified, socket string, uid, gid uint32, recheck func() error) (pluginmodel.Transport, error) {
	return Service(ctx, k, v, socket, uid, gid, recheck)
}

// NoSocket reports whether err says nothing listened on the socket.
func (Dialer) NoSocket(err error) bool { return errors.Is(err, ErrNoSocket) }

// SocketDir reports whether err says the socket directory is not the unit's.
func (Dialer) SocketDir(err error) bool { return errors.Is(err, ErrSocketDir) }
