package setup

import (
	"context"
	"crypto/x509"
	"errors"
	"os/user"

	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/setupstore"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// testBackend is the local setup's backend for the tests inside this
// package, which cannot import internal/app/setupbackend (it imports this
// package): the calls they make go to the same adapters setupbackend
// forwards to, and any other call panics on the nil LocalBackend.
type testBackend struct{ LocalBackend }

var errNoConnection = errors.New("this test opens no connection")

func (testBackend) DatabaseError(err error) (string, string, bool) {
	return setupstore.Store{}.DatabaseError(err)
}

func (testBackend) ExplainTrust(dsn string, set *trustprofile.Set) (trustprofile.Applied, error) {
	return pgdial.ExplainWith(dsn, set)
}

func (testBackend) AgentConnString(adminURL, role, password string) (string, error) {
	return guard.AgentConnString(adminURL, role, password)
}

func (testBackend) Trust() *trustprofile.Set { return pgdial.Trust() }

func (testBackend) OSUsers() Users { return noUsers{} }

// noUsers is a computer with no OS user but this engine's own.
type noUsers struct{}

var errNoUser = errors.New("this test looks no OS user up")

func (noUsers) Lookup(string) (*user.User, error)     { return nil, errNoUser }
func (noUsers) LookupID(string) (*user.User, error)   { return nil, errNoUser }
func (noUsers) GroupIDs(*user.User) ([]string, error) { return nil, errNoUser }
func (noUsers) Self() int                             { return 4000 }

func (testBackend) Connect(context.Context, string) (Conn, error) { return nil, errNoConnection }

func (testBackend) ConnectPinned(context.Context, string, *trustprofile.Profile) (Conn, error) {
	return nil, errNoConnection
}

func (testBackend) FetchChain(context.Context, string, int) ([]*x509.Certificate, error) {
	return nil, errNoConnection
}
