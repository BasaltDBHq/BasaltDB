package handoff

import (
	"context"
	"crypto/x509"
	"net/netip"
	"os"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// Resolver looks up a host name. *net.Resolver's LookupNetIP is one, and
// lib/sysdns's outside tests.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Handoff is the engine's connect-only setup (handoff.Pending).
type Handoff interface {
	State() State
	StatusCollect(ctx context.Context) State
	Confirm(ctx context.Context, setupID string, db setupcode.Address, yes bool) (Answer, error)
}

// SetupFinisher finishes an agent's pending setup on the engine's machine.
type SetupFinisher interface {
	// PendingRecorded logs in with the agent's .pending credential, when
	// there is one for the same database and role as the engine's, and
	// reports whether setup id is recorded. has is false when there is no
	// such credential or the database refuses its login.
	PendingRecorded(ctx context.Context, id uuid.UUID) (recorded, has bool, err error)
	// Finish clears setup id from the agent's entry in engine.json under the
	// agent's lock, after moving the .pending credential PendingRecorded
	// logged in with over the credential file when promote is set. A config
	// whose pending setup is no longer id is left as it is.
	Finish(ctx context.Context, id string, promote bool) error
}

// ProbeCache keeps Cached between processes, so a reached PREVIEW address
// is probed once per flow whichever process collects it (CONTRACT.md, The
// engine and a connect-only code, Collecting).
type ProbeCache interface {
	Load(setupID string) (Cached, bool)
	Save(c Cached) error
}

// CacheFile is the file a FileCache keeps its probe in, read and written
// whole (handofffiles.ProbeCacheFile in the engine's state directory).
type CacheFile interface {
	Read() (string, error)
	Write(raw []byte) error
}

// Signer signs with the engine's signing key: *channel.EngineKeys.
type Signer interface {
	Sign(context channel.SigningContext, body []byte) ([]byte, error)
	PublicKeySPKI() []byte
}

// FinishFiles reaches an agent's .pending credential, its credential file,
// its .lock and the engine config the finisher clears the setup from.
type FinishFiles interface {
	// ReadPending reads the .pending credential, trimmed: an error wrapping
	// fs.ErrNotExist when there is none, and an error when the file holds
	// more than limit bytes.
	ReadPending(limit int) (string, os.FileInfo, error)
	// Promote moves the .pending credential over the credential file, once
	// .pending still names the file read (pending).
	Promote(pending os.FileInfo) error
	Lock() (func(), error)
	ClearSetup(agent, id string) (bool, error)
}

// AgentLogin is the agent's own connection the finisher reads with.
type AgentLogin interface {
	// SetupRecorded reports whether setup id is recorded in the database.
	SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error)
	Close(ctx context.Context) error
}

// Collector asks the connect service for the address and reports whether
// the engine reached a PREVIEW one: *Client.
type Collector interface {
	Collect(ctx context.Context, setupID, fingerprint string) (Collected, error)
	Report(ctx context.Context, setupID, fingerprint string, a setupcode.Address, r Reach) error
}

// AddressProber probes an address with logins bound to fail: Prober.
// Resolve checks the address and resolves its host once; ProbeAt probes the
// address it resolved to.
type AddressProber interface {
	Resolve(ctx context.Context, a setupcode.Address) (netip.Addr, error)
	// Approve checks, with the TLS handshake alone, the certificate
	// authority the person trusted on the connect page against the chain
	// the server presents to this machine.
	Approve(ctx context.Context, a setupcode.Address, ip netip.Addr, approved string) (Pin, error)
	ProbeAt(ctx context.Context, a setupcode.Address, ip netip.Addr, user string, pin Pin) (Probed, error)
}

// Files are the agent's files and its entry in engine.json, as the engine
// reaches them. Lock is the agent's lock, the one basalt init --remote
// takes; the other methods run under it.
type Files interface {
	Lock() (unlock func(), err error)
	// PendingSetup is the agent's pending setup in engine.json now; false
	// when none.
	PendingSetup() (config.Setup, bool, error)
	// ReadSecret reads the agent's .secret: the password init generated.
	ReadSecret() (string, error)
	// WriteCredential writes the agent's credential file, 0600 and
	// atomically; it refuses to replace one that exists.
	WriteCredential(dsn string) error
	// RemoveSecret removes .secret; a missing one is not an error.
	RemoveSecret() error
	// WritePin writes the pin of top (caOnly: it verifies the chain alone)
	// for host to trust.d, unless that pin is there already; it refuses
	// when another trust profile covers host by then.
	WritePin(host string, top *x509.Certificate, caOnly bool) error
	// ConfirmSetup clears awaitingAddress from pending setup id.
	ConfirmSetup(id string) error
	// RefuseSetup replaces awaitingAddress with refused in pending setup id.
	RefuseSetup(id string) error
	// MarkAddressInvalid sets addressInvalid in pending setup id: the next
	// basalt init --remote forgets it and makes a recovery code.
	MarkAddressInvalid(id string) error
}

// RepinProber resolves the credential's host and reads its chain: Prober.
type RepinProber interface {
	Resolve(ctx context.Context, a setupcode.Address) (netip.Addr, error)
	// Repin checks approved against the chain the server presents to this
	// machine, the engine's own pin for the host left out.
	Repin(ctx context.Context, a setupcode.Address, ip netip.Addr, approved string) (Pin, error)
}

// RepinFiles are the agent's entry in engine.json and the config's trust.d.
type RepinFiles interface {
	// PendingSetup is the agent's pending setup in engine.json now.
	PendingSetup() (config.Setup, bool, error)
	// ReplacePin replaces the engine's own pin for host with top's (caOnly:
	// it verifies the chain alone), under the config lock; it refuses when
	// another profile covers host.
	ReplacePin(host string, top *x509.Certificate, caOnly bool) error
}

// StoppedFiles are the agent's files a confirmation the engine stopped in
// is finished on.
type StoppedFiles interface {
	// CredentialExists reports whether the agent's credential file exists,
	// not following a link.
	CredentialExists() (bool, error)
	Lock() (unlock func(), err error)
	// RemoveSecret removes .secret; a missing one is not an error.
	RemoveSecret() error
	// ConfirmSetup clears awaitingAddress from pending setup id.
	ConfirmSetup(id string) error
}

// AgentFiles reaches an agent's credential file, and for the setup
// finisher its .pending, its .lock and the engine config the finisher
// clears the setup from (FinishFiles): by path (handofffiles.PathFiles) or, started as
// root, through opened directories (handofffiles.RootFiles).
type AgentFiles interface {
	FinishFiles
	ReadCredential() (string, error)
	Close()
}
