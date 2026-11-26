package setup

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// This file is the engine's side of what the connect service must agree on
// with it byte for byte (CONTRACT.md, Connect): where a database may be,
// the signed texts of the address hand-off and the reach check, the passkey
// check code, and the Supabase ref and canonical form of an address. Each
// is a forward to the engine's own function, so the two cannot drift.

// AddressAllowed reports whether a database may be at a: a global unicast
// address outside every refused range (CONTRACT.md, Connect, Where the
// runner connects).
func AddressAllowed(a netip.Addr) bool { return handoff.Allowed(a) }

// RefusedPrefixes is a copy of the ranges AddressAllowed refuses, IPv4 and
// IPv6.
func RefusedPrefixes() []netip.Prefix { return handoff.RefusedPrefixes() }

// Resolver looks up a host name. *net.Resolver and SystemResolver are one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SystemResolver resolves with the system's DNS (net.DefaultResolver when R
// is nil). It asks for A and AAAA records separately, so an A record is an
// IPv4 address.
type SystemResolver struct{ R *net.Resolver }

// LookupNetIP returns the A addresses and then the AAAA addresses of host.
func (s SystemResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return handoff.SystemResolver(s).LookupNetIP(ctx, network, host)
}

// PickAddress resolves host once and returns the one address to connect
// to, so a second lookup cannot move the connection elsewhere: every
// address the name resolves to must be allowed (AddressRefused otherwise),
// and IPv4 is preferred. An IP literal is checked as it is.
func PickAddress(ctx context.Context, r Resolver, host string) (netip.Addr, error) {
	return handoff.Pick(ctx, r, host)
}

// AddressRefused reports whether err is PickAddress refusing an address
// that is not allowed, rather than a host that does not resolve.
func AddressRefused(err error) bool { return errors.Is(err, setupcode.ErrAddressInvalid) }

// The connect service's audience and the signing contexts of the engine's
// requests to it (CONTRACT.md, Vault channel, Primitives and encodings).
// A signed text is its context line followed by its body.
const (
	ConnectAudience       = channel.ConnectAudience
	ConnectCollectContext = string(channel.ContextConnectCollect)
	ConnectReachContext   = string(channel.ContextConnectReach)
)

// ConnectCollectBody is what follows ConnectCollectContext in a
// CollectAddress signature: the audience, the setupId, the setup
// fingerprint as printed and the time, one per line.
func ConnectCollectBody(setupID, fingerprint, at string) []byte {
	return channel.ConnectCollectBody(setupID, fingerprint, at)
}

// ConnectReachBody is what follows ConnectReachContext in a ReportReach
// signature: the collect body's lines, then a's host, port, database and
// Supabase ref, the result and the reason. The engine signs a.Canonical();
// an absent ref and the reason of a REACHABLE report are empty lines.
func ConnectReachBody(setupID, fingerprint, at string, a Target, result, reason string) []byte {
	return channel.ConnectReachBody(setupID, fingerprint, at, a.Host, a.Port, a.Database, a.SupabaseRef, result, reason)
}

// VerifyConnectCollect checks a CollectAddress signature (64 bytes r || s)
// by the engine key engineKey (91-byte P-256 SPKI DER with an uncompressed
// point; any other encoding is refused). It returns nil for a valid signature.
func VerifyConnectCollect(engineKey, signature []byte, setupID, fingerprint, at string) error {
	return channel.VerifyKeySignature(engineKey, channel.ContextConnectCollect, channel.ConnectCollectBody(setupID, fingerprint, at), signature)
}

// VerifyConnectReach checks a ReportReach signature as VerifyConnectCollect
// checks a CollectAddress one, over ConnectReachBody. It returns nil for a
// valid signature.
func VerifyConnectReach(engineKey, signature []byte, setupID, fingerprint, at string, a Target, result, reason string) error {
	return channel.VerifyKeySignature(engineKey, channel.ContextConnectReach,
		channel.ConnectReachBody(setupID, fingerprint, at, a.Host, a.Port, a.Database, a.SupabaseRef, result, reason), signature)
}

// PasskeyRegistrationPrefix starts the code the passkey registration page
// shows (basalt-passkey.1.<base64url(json)>).
const PasskeyRegistrationPrefix = passkey.RegistrationResponsePrefix

// CheckCode is the passkey check code of a P-256 key's 32-byte coordinates
// (CONTRACT.md, Connect, The passkey check code): five groups of four
// lowercase hex digits.
func CheckCode(x, y []byte) string { return passkey.CheckCode(x, y) }

// SupabaseRef is the Supabase project ref a connection to host as user
// names, or "": the ref of a direct host db.<ref>.supabase.co, or of a
// pooler user <role>.<ref> on Supabase's pooler.
func SupabaseRef(host, user string) string {
	return setupcode.ConnTarget(host, 0, "", user).SupabaseRef
}

// Canonical is t as a reach report names and compares it (CONTRACT.md,
// Connect, The reach check): the host and the Supabase ref in lowercase,
// the port and the database as given.
func (t Target) Canonical() Target { return Target(setupcode.Address(t).Canonical()) }
