//go:build unix

package app

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/platform/keyfile"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/trustdir"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/service/handoff"
	"github.com/basaltdbhq/basaltdb/internal/testkit/connecttest"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// repinHost is the database's name: the connect service reaches it
// through a recording proxy, the engine reads its chain from a server that
// presents the new certificate.
const repinHost = "db.internal.example.com"

// rotationFixture is an installed agent whose engine pinned repinHost to
// an old CA, a certificateChanged AGENT code for it, the connect service
// and the server that now presents the new CA.
type rotationFixture struct {
	d       *guardtest.DB
	cfg     string
	setup   config.Setup
	code    string
	keys    *channel.EngineKeys
	oldCA   *x509.Certificate
	newCA   *x509.Certificate
	newDial func(ctx context.Context, network, addr string) (net.Conn, error)
	srv     *connecttest.Server
	rpc     connectv1connect.SetupServiceClient
	base    string
	pasted  string
}

func newRotationFixture(t *testing.T) rotationFixture {
	t.Helper()
	d := guardtest.New(t).WithDemo(t)
	d.NewAgent(t, "bot", []string{"public.leads"}, []string{"public.leads"})
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, person.Credential(), "app"))

	dir, err := os.MkdirTemp("", "rpin")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	cfg := filepath.Join(dir, "engine.json")
	keys, err := keyfile.LoadOrCreateKeys(filepath.Join(dir, channel.KeyFileName), time.Now)
	require.NoError(t, err)

	oldCA, _ := trustprofiletest.Chain(t, repinHost)
	_, _, err = trustdir.Pin(cfg, repinHost, oldCA, false)
	require.NoError(t, err)
	newCA, leaf := trustprofiletest.Chain(t, repinHost)
	newDial := trustprofiletest.Serve(t, tls.Certificate{Certificate: append(leaf.Certificate, newCA.Raw), PrivateKey: leaf.PrivateKey})

	ac := d.Admin.Config()
	proxy := connecttest.StartProxy(t, repinHost, net.JoinHostPort(ac.Host, strconv.Itoa(int(ac.Port))))
	srv, base := connecttest.StartWith(t, connecttest.Options{Dial: proxy.Connect})
	u, err := url.Parse(d.URL)
	require.NoError(t, err)
	u.Host = net.JoinHostPort(repinHost, "5432")
	q := u.Query()
	q.Set("sslmode", "verify-full")
	u.RawQuery = q.Encode()
	target, err := setupcode.TargetOf(u)
	require.NoError(t, err)

	id, expires, err := setupcode.NewSetupID(time.Now(), rand.Reader)
	require.NoError(t, err)
	p := setupcode.Payload{
		Format: setupcode.Format, SetupID: id, Kind: setupcode.KindAgent, Prefix: d.Names.Prefix, Target: &target,
		Guard: setupcode.Guard{To: guard.LatestVersion()}, Build: "1.0.0", ExpiresAt: expires,
		Engine:   &setupcode.Engine{PublicKey: base64.RawURLEncoding.EncodeToString(keys.PublicKeySPKI())},
		TrustPin: trustprofile.DERSHA256(oldCA),
		Agent:    &setupcode.Agent{Name: "bot", Write: []string{"public.leads"}, Read: []string{}, StatementTimeoutMs: 30000},
	}
	code, err := setupcode.Encode(p)
	require.NoError(t, err)
	return rotationFixture{
		d: d, cfg: cfg, code: code, keys: keys, oldCA: oldCA, newCA: newCA, newDial: newDial, srv: srv, base: base, pasted: u.String(),
		rpc: connectv1connect.NewSetupServiceClient(http.DefaultClient, base),
		setup: config.Setup{
			SetupID: id, Kind: string(setupcode.KindAgent), GuardVersion: guard.LatestVersion(), ExpiresAt: expires,
			Code: code, Fingerprint: p.Fingerprint(), CertificateChanged: true,
		},
	}
}

// approve is the page: the summary carries the bot's pin, CheckSetup and
// RunSetup with the trustRoot the person trusted.
func (f rotationFixture) approve(t *testing.T, trustRoot string) {
	t.Helper()
	ctx := context.Background()
	desc, err := f.rpc.DescribeSetup(ctx, connect.NewRequest(&connectv1.DescribeSetupRequest{Code: f.code}))
	require.NoError(t, err)
	require.Equal(t, trustprofile.DERSHA256(f.oldCA), desc.Msg.GetSummary().GetTrustPin(), "the page's Was:")
	chk, err := f.rpc.CheckSetup(ctx, connect.NewRequest(&connectv1.CheckSetupRequest{Code: f.code, DatabaseUrl: f.pasted, TrustRoot: trustRoot}))
	require.NoError(t, err)
	require.False(t, chk.Msg.GetPasskeyNeeded())
	require.NotEmpty(t, chk.Msg.GetPasskeys())
	run, err := f.rpc.RunSetup(ctx, connect.NewRequest(&connectv1.RunSetupRequest{Code: f.code, DatabaseUrl: f.pasted, TrustRoot: trustRoot}))
	require.NoError(t, err)
	require.Empty(t, run.Msg.GetTicket(), "a code with a target gets no ticket")
	require.Equal(t, trustRoot, f.srv.HeldTrustRoot(f.setup.SetupID), "a SET_UP hold of the target with the trustRoot")
}

// memoryPending is engine.json's pending setup, held in memory; the pin is
// replaced in the fixture's real trust.d.
type memoryPending struct {
	repinFiles
	setup config.Setup
}

func (m memoryPending) PendingSetup() (config.Setup, bool, error) { return m.setup, true, nil }

// engineRepin is the engine's collect loop for the setup, reading the
// chain from the server with the new certificate.
func (f rotationFixture) engineRepin(t *testing.T) *handoff.Repin {
	t.Helper()
	r, err := handoff.NewRepin(handoff.RepinOptions{
		Setup:      f.setup,
		Credential: setupcode.Address{Host: repinHost, Port: 5432, Database: f.d.Admin.Config().Database},
		Collector:  handoff.NewClient(nil, f.base, f.keys, time.Now),
		Prober: handoff.Prober{
			Resolver: staticResolver{netip.MustParseAddr("8.8.8.8")},
			Dial:     f.newDial,
			Profiles: trustdir.Set(f.cfg), ConnConfig: pgdial.ConnConfigTrusting,
		},
		Files: memoryPending{repinFiles: repinFiles{handoffFiles{configPath: f.cfg, agent: "bot"}}, setup: f.setup},
		Log:   slog.New(slog.DiscardHandler), Now: time.Now,
	})
	require.NoError(t, err)
	return r
}

type staticResolver struct{ ip netip.Addr }

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{r.ip}, nil
}

func pinnedTo(t *testing.T, cfg string) *x509.Certificate {
	t.Helper()
	p := trustdir.Set(cfg).For(repinHost)
	require.NotNil(t, p)
	require.Equal(t, trustprofile.PinName(repinHost), p.Name)
	require.Len(t, p.Certificates(), 1)
	return p.Certificates()[0]
}

// Persona 2's trust rotation end to end: the certificateChanged code runs
// on the page with the trustRoot the person trusted, the service records
// the pin in the ledger and holds the target, and the engine replaces its
// pin only once its own reading of the chain shows that trustRoot.
func TestTrustRotationOnPersona2(t *testing.T) {
	t.Parallel()
	f := newRotationFixture(t)
	f.approve(t, trustprofile.DERSHA256(f.newCA))
	var n int
	require.NoError(t, f.d.Admin.QueryRow(context.Background(),
		`SELECT count(seq)::int FROM basalt_meta.ledger WHERE kind = 'TRUST_PIN_RECORDED'`).Scan(&n))
	require.Equal(t, 1, n, "RunSetup recorded the certificate it logged in against")

	r := f.engineRepin(t)
	require.True(t, pinnedTo(t, f.cfg).Equal(f.oldCA))
	require.False(t, r.Step(context.Background()))
	require.True(t, r.Done())
	require.True(t, pinnedTo(t, f.cfg).Equal(f.newCA), "the engine's pin is the new certificate")
	entries, err := os.ReadDir(trustdir.Path(f.cfg))
	require.NoError(t, err)
	require.Len(t, entries, 2, "the profile and the new PEM file; the old one is removed")
	recorded, err := setupRecordedFor(f.d.Admin, f.setup.SetupID)
	require.NoError(t, err)
	require.True(t, recorded, "the setup finishes as any pending setup does")
}

// A trustRoot the engine's own reading does not show pins nothing: the
// service alone adds no trust.
func TestTrustRotationMismatchPinsNothing(t *testing.T) {
	t.Parallel()
	f := newRotationFixture(t)
	elsewhere, _ := trustprofiletest.Chain(t, repinHost)
	f.approve(t, trustprofile.DERSHA256(elsewhere))
	r := f.engineRepin(t)
	require.True(t, r.Step(context.Background()), "it keeps collecting")
	require.False(t, r.Done())
	require.Equal(t, handoff.ProblemTrustRootMismatch, r.Problem())
	require.True(t, pinnedTo(t, f.cfg).Equal(f.oldCA), "the old pin stays")
}

func setupRecordedFor(conn *pgx.Conn, id string) (bool, error) {
	var ok bool
	err := conn.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM basalt_meta.setups WHERE setup_id = $1::uuid)`, id).Scan(&ok)
	return ok, err
}
