package connecttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/internal/channel"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// The address hand-off (CONTRACT.md, Connect, The address hand-off): the
// hold, the ticket and the three calls, in the contract's check order.

// HoldLife is how long a hold lives after RunSetup (30 minutes).
const HoldLife = 30 * time.Minute

// clockSkew is how far CollectAddress's time may be from the service's.
const clockSkew = 5 * time.Minute

// ticketDomain keeps a ticket's keyed hash apart from a passkey
// challenge's.
const ticketDomain = "basalt-connect-ticket.1\n"

// The states HandoffStatus and OfferAddress answer.
const (
	stateHeld      = "HELD"
	stateCollected = "COLLECTED"
	stateUnknown   = "UNKNOWN"
)

// runElsewhere is RUN_ELSEWHERE's fixed message: it names nothing of the
// other database.
const runElsewhere = "This setup code was already used with a different database. If that was not you, someone else has your link: tell your bot to start over."

// hold is an address held for the engine of a connect-only setup.
type hold struct {
	Address     setup.Target `json:"address"`
	EngineKey   string       `json:"engineKey"`
	SetupID     string       `json:"setupId"`
	Fingerprint string       `json:"fingerprint"`
	Expires     time.Time    `json:"expires"`
	CollectedAt *time.Time   `json:"collectedAt,omitempty"`
}

// holds are the service's holds, in memory only.
type holds struct {
	mu sync.Mutex
	m  map[string]hold
}

// live is the unexpired hold for setupID.
func (s *Server) live(setupID string) (hold, bool) {
	s.holds.mu.Lock()
	defer s.holds.mu.Unlock()
	h, ok := s.holds.m[setupID]
	if !ok || !s.Now().Before(h.Expires) {
		return hold{}, false
	}
	return h, true
}

func (s *Server) put(h hold) {
	s.holds.mu.Lock()
	defer s.holds.mu.Unlock()
	if s.holds.m == nil {
		s.holds.m = map[string]hold{}
	}
	s.holds.m[h.SetupID] = h
}

// Restart drops every hold, as a restart of the service does.
func (s *Server) Restart() {
	s.holds.mu.Lock()
	defer s.holds.mu.Unlock()
	s.holds.m = nil
}

// Held is the address the service holds for setupID, for tests.
func (s *Server) Held(setupID string) (setup.Target, bool) {
	h, ok := s.live(setupID)
	return h.Address, ok
}

// holdFor holds the address of a connect-only setup that just ran (or ran
// again), for 30 minutes from now, and returns its ticket.
func (s *Server) holdFor(d setup.Description, at setup.Target) (string, error) {
	h := hold{Address: at, EngineKey: d.EngineKey, SetupID: d.SetupID, Fingerprint: d.Fingerprint, Expires: s.Now().Add(HoldLife).UTC().Truncate(time.Second)}
	s.put(h)
	return s.ticket(h)
}

// otherTarget reports a live hold for d's setup with another address than
// at: RUN_ELSEWHERE.
func (s *Server) otherTarget(d setup.Description, at setup.Target) bool {
	h, ok := s.live(d.SetupID)
	return ok && h.Address != at
}

// ticket is h with a keyed hash, as the page keeps it.
func (s *Server) ticket(h hold) (string, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	body := b64.EncodeToString(raw)
	return body + "." + s.ticketMAC(body), nil
}

func (s *Server) ticketMAC(body string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(ticketDomain + body))
	return b64.EncodeToString(m.Sum(nil))
}

// fromTicket checks a ticket's hash and expiry.
func (s *Server) fromTicket(t string) (hold, error) {
	body, mac, ok := strings.Cut(t, ".")
	if !ok || !hmac.Equal([]byte(mac), []byte(s.ticketMAC(body))) {
		return hold{}, handoffUnknown()
	}
	raw, err := b64.DecodeString(body)
	if err != nil {
		return hold{}, handoffUnknown()
	}
	var h hold
	if err := json.Unmarshal(raw, &h); err != nil || !s.Now().Before(h.Expires) {
		return hold{}, handoffUnknown()
	}
	return h, nil
}

func handoffUnknown() error {
	return refusal(connect.CodeNotFound, "HANDOFF_UNKNOWN", "This hand-off is not known.")
}

// CollectAddress is the engine's call: the time first, then the hold, then
// the signature, so a flood of made-up keys costs a map lookup.
func (s *Server) CollectAddress(_ context.Context, r *connect.Request[connectv1.CollectAddressRequest]) (*connect.Response[connectv1.CollectAddressResponse], error) {
	m := r.Msg
	at, err := time.Parse(time.RFC3339, m.GetTime())
	if err != nil || at.Sub(s.Now()).Abs() > clockSkew {
		return nil, refusal(connect.CodeInvalidArgument, "CLOCK_SKEW", "The engine's clock is more than 5 minutes off.")
	}
	h, ok := s.live(m.GetSetupId())
	if !ok || h.EngineKey != m.GetEnginePublicKey() || !verifyCollect(h, m) {
		s.collectsRefused.Add(1)
		return nil, handoffUnknown()
	}
	if h.CollectedAt == nil {
		now := s.Now().UTC().Truncate(time.Second)
		h.CollectedAt = &now
		s.put(h)
	}
	return connect.NewResponse(&connectv1.CollectAddressResponse{Address: target(h.Address)}), nil
}

// verifyCollect checks the request's signature by the hold's engine key
// over the audience, the setupId, the hold's fingerprint and the time.
func verifyCollect(h hold, m *connectv1.CollectAddressRequest) bool {
	spki, err := b64.DecodeString(h.EngineKey)
	if err != nil {
		return false
	}
	key, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return false
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := b64.DecodeString(m.GetSignature())
	if err != nil {
		return false
	}
	body := channel.ConnectCollectBody(h.SetupID, h.Fingerprint, m.GetTime())
	return channel.VerifySignature(pub, channel.ContextConnectCollect, body, sig) == nil
}

// HandoffStatus is the page's poll: UNKNOWN without a hold for the
// ticket's address, else HELD or COLLECTED with a new ticket.
func (s *Server) HandoffStatus(_ context.Context, r *connect.Request[connectv1.HandoffStatusRequest]) (*connect.Response[connectv1.HandoffStatusResponse], error) {
	t, err := s.fromTicket(r.Msg.GetTicket())
	if err != nil {
		return nil, err
	}
	h, ok := s.live(t.SetupID)
	if !ok || h.Address != t.Address {
		return connect.NewResponse(&connectv1.HandoffStatusResponse{State: stateUnknown}), nil
	}
	fresh, err := s.ticket(h)
	if err != nil {
		return nil, err
	}
	out := &connectv1.HandoffStatusResponse{State: stateHeld, Ticket: fresh}
	if h.CollectedAt != nil {
		out.State, out.CollectedAt = stateCollected, h.CollectedAt.Format(time.RFC3339)
	}
	return connect.NewResponse(out), nil
}

// OfferAddress puts a hold back after a restart, with the ticket's expiry
// and collected state; a hold that exists stays as it is.
func (s *Server) OfferAddress(_ context.Context, r *connect.Request[connectv1.OfferAddressRequest]) (*connect.Response[connectv1.OfferAddressResponse], error) {
	t, err := s.fromTicket(r.Msg.GetTicket())
	if err != nil {
		return nil, err
	}
	if _, ok := s.live(t.SetupID); !ok {
		s.put(t)
	}
	state := stateHeld
	if t.CollectedAt != nil {
		state = stateCollected
	}
	return connect.NewResponse(&connectv1.OfferAddressResponse{State: state}), nil
}
