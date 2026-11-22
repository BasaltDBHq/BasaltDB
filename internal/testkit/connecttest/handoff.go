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
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/pkg/setup"
)

// The address hand-off (CONTRACT.md, Connect, The address hand-off) and the
// reach check (Connect, The reach check): the hold in its two phases, the
// ticket and the four calls, in the contract's check order. The fake has no
// limits, so it has no caps on PREVIEW holds either.

// HoldLife is how long a hold lives after CheckSetup or RunSetup (30
// minutes).
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

// The phases of a hold.
const (
	PhasePreview = "PREVIEW"
	PhaseSetUp   = "SET_UP"
)

// The results and reasons of ReportReach.
const (
	resultReachable   = "REACHABLE"
	resultUnreachable = "UNREACHABLE"
)

var reachReasons = map[string]bool{"ADDRESS_REFUSED": true, "NO_ROUTE": true, "TLS_NOT_VERIFIED": true, "TIMEOUT": true, "TRUST_ROOT_MISMATCH": true}

// runElsewhere is RUN_ELSEWHERE's fixed message: it names nothing of the
// other database.
const runElsewhere = "This setup code was already used with a different database. If that was not you, someone else has your link: tell your bot to start over."

// hold is an address held for the engine of a connect-only setup, in its
// phase. A ticket records every field but Reach, which only the hold keeps.
type hold struct {
	Address     setup.Target `json:"address"`
	EngineKey   string       `json:"engineKey"`
	SetupID     string       `json:"setupId"`
	Fingerprint string       `json:"fingerprint"`
	Expires     time.Time    `json:"expires"`
	Phase       string       `json:"phase"`
	// TrustRoot is the certificate authority the login was verified
	// against, "" for none; CollectAddress returns it.
	TrustRoot   string     `json:"trustRoot,omitempty"`
	CollectedAt *time.Time `json:"collectedAt,omitempty"`
	Reach       *Reach     `json:"-"`
}

// Reach is the newest report the engine made for a hold's address.
type Reach struct {
	Result, Reason string
	At             time.Time
}

// canonical is t as reports and tickets are compared: the host and the
// ref in lowercase.
func canonical(t setup.Target) setup.Target {
	t.Host, t.SupabaseRef = strings.ToLower(t.Host), strings.ToLower(t.SupabaseRef)
	return t
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

// HeldTrustRoot is the trustRoot of the hold for setupID, "" without one.
func (s *Server) HeldTrustRoot(setupID string) string {
	h, _ := s.live(setupID)
	return h.TrustRoot
}

// HeldPhase is the phase of the hold for setupID, "" without one.
func (s *Server) HeldPhase(setupID string) string {
	h, _ := s.live(setupID)
	return h.Phase
}

// Reached is the reach report the service kept for setupID's hold.
func (s *Server) Reached(setupID string) (Reach, bool) {
	h, ok := s.live(setupID)
	if !ok || h.Reach == nil {
		return Reach{}, false
	}
	return *h.Reach, true
}

// holdFor holds the address of a connect-only setup that just ran (or ran
// again), as a SET_UP hold for 30 minutes from now, replacing any hold, and
// returns its ticket.
func (s *Server) holdFor(d setup.Description, at setup.Target, trustRoot string) (string, error) {
	h := hold{Address: at, EngineKey: d.EngineKey, SetupID: d.SetupID, Fingerprint: d.Fingerprint, Expires: s.Now().Add(HoldLife).UTC().Truncate(time.Second), Phase: PhaseSetUp, TrustRoot: trustRoot}
	s.put(h)
	return s.ticket(h)
}

// previewFor makes a PREVIEW hold for at and returns its ticket, replacing
// a PREVIEW hold, never a SET_UP one: then it makes none and returns "".
func (s *Server) previewFor(d setup.Description, at setup.Target, trustRoot string) (string, error) {
	h := hold{Address: at, EngineKey: d.EngineKey, SetupID: d.SetupID, Fingerprint: d.Fingerprint, Expires: s.Now().Add(HoldLife).UTC().Truncate(time.Second), Phase: PhasePreview, TrustRoot: trustRoot}
	s.holds.mu.Lock()
	if old, ok := s.holds.m[d.SetupID]; ok && s.Now().Before(old.Expires) && old.Phase == PhaseSetUp {
		s.holds.mu.Unlock()
		return "", nil
	}
	if s.holds.m == nil {
		s.holds.m = map[string]hold{}
	}
	s.holds.m[d.SetupID] = h
	s.holds.mu.Unlock()
	return s.ticket(h)
}

// setUpHold is the live SET_UP hold for setupID: a PREVIEW hold counts as
// none for RUN_ELSEWHERE and for running the same code again.
func (s *Server) setUpHold(setupID string) (hold, bool) {
	h, ok := s.live(setupID)
	return h, ok && h.Phase == PhaseSetUp
}

// otherTarget reports a live SET_UP hold for d's setup with another
// address than at: RUN_ELSEWHERE.
func (s *Server) otherTarget(d setup.Description, at setup.Target) bool {
	h, ok := s.setUpHold(d.SetupID)
	return ok && canonical(h.Address) != canonical(at)
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
	if !ok || h.EngineKey != m.GetEnginePublicKey() ||
		!verifySigned(h, channel.ContextConnectCollect, channel.ConnectCollectBody(h.SetupID, h.Fingerprint, m.GetTime()), m.GetSignature()) {
		s.collectsRefused.Add(1)
		return nil, handoffUnknown()
	}
	if h.CollectedAt == nil {
		now := s.Now().UTC().Truncate(time.Second)
		h.CollectedAt = &now
		s.put(h)
	}
	return connect.NewResponse(&connectv1.CollectAddressResponse{Address: target(h.Address), Phase: h.Phase, TrustRoot: h.TrustRoot}), nil
}

// verifySigned checks a signature by the hold's engine key over context
// and body.
func verifySigned(h hold, context channel.SigningContext, body []byte, signature string) bool {
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
	sig, err := b64.DecodeString(signature)
	if err != nil {
		return false
	}
	return channel.VerifySignature(pub, context, body, sig) == nil
}

// ReportReach is the engine's report, checked in CollectAddress's order:
// the time, the hold, its key, the signature; a result or reason outside
// the contract's is HANDOFF_UNKNOWN too. The hold keeps the newest report
// by time for its own address (a later arrival wins a tie) and ignores one
// for another address or an older one, answering it as accepted.
func (s *Server) ReportReach(_ context.Context, r *connect.Request[connectv1.ReportReachRequest]) (*connect.Response[connectv1.ReportReachResponse], error) {
	m := r.Msg
	at, err := time.Parse(time.RFC3339, m.GetTime())
	if err != nil || at.Sub(s.Now()).Abs() > clockSkew {
		return nil, refusal(connect.CodeInvalidArgument, "CLOCK_SKEW", "The engine's clock is more than 5 minutes off.")
	}
	a := m.GetAddress()
	h, ok := s.live(m.GetSetupId())
	if !ok || h.EngineKey != m.GetEnginePublicKey() || a == nil {
		s.reportsRefused.Add(1)
		return nil, handoffUnknown()
	}
	body := channel.ConnectReachBody(h.SetupID, h.Fingerprint, m.GetTime(), a.GetHost(), int(a.GetPort()), a.GetDatabase(), a.GetSupabaseRef(), m.GetResult(), m.GetReason())
	valid := (m.GetResult() == resultReachable && m.GetReason() == "") || (m.GetResult() == resultUnreachable && reachReasons[m.GetReason()])
	if !verifySigned(h, channel.ContextConnectReach, body, m.GetSignature()) || !valid {
		s.reportsRefused.Add(1)
		return nil, handoffUnknown()
	}
	reported := setup.Target{Host: a.GetHost(), Port: int(a.GetPort()), Database: a.GetDatabase(), SupabaseRef: a.GetSupabaseRef()}
	s.holds.mu.Lock()
	defer s.holds.mu.Unlock()
	cur, ok := s.holds.m[h.SetupID]
	if ok && cur.Expires.Equal(h.Expires) && cur.Phase == h.Phase && canonical(cur.Address) == canonical(reported) && (cur.Reach == nil || !at.Before(cur.Reach.At)) {
		cur.Reach = &Reach{Result: m.GetResult(), Reason: m.GetReason(), At: at}
		s.holds.m[h.SetupID] = cur
	}
	return connect.NewResponse(&connectv1.ReportReachResponse{}), nil
}

// ReportsRefused is how many ReportReach calls were answered
// HANDOFF_UNKNOWN.
func (s *Server) ReportsRefused() int64 { return s.reportsRefused.Load() }

// HandoffStatus is the page's poll: UNKNOWN without a hold for the
// ticket's address (and, for a set-up ticket, with a PREVIEW hold), else
// HELD or COLLECTED with a new ticket, the hold's phase and its reach
// report.
func (s *Server) HandoffStatus(_ context.Context, r *connect.Request[connectv1.HandoffStatusRequest]) (*connect.Response[connectv1.HandoffStatusResponse], error) {
	t, err := s.fromTicket(r.Msg.GetTicket())
	if err != nil {
		return nil, err
	}
	h, ok := s.live(t.SetupID)
	if !ok || canonical(h.Address) != canonical(t.Address) || (t.Phase == PhaseSetUp && h.Phase != PhaseSetUp) {
		return connect.NewResponse(&connectv1.HandoffStatusResponse{State: stateUnknown}), nil
	}
	fresh, err := s.ticket(h)
	if err != nil {
		return nil, err
	}
	out := &connectv1.HandoffStatusResponse{State: stateHeld, Ticket: fresh, Phase: h.Phase}
	if h.CollectedAt != nil {
		out.State, out.CollectedAt = stateCollected, h.CollectedAt.Format(time.RFC3339)
	}
	if h.Reach != nil {
		out.Reach = &connectv1.Reach{Result: h.Reach.Result, Reason: h.Reach.Reason, ReportedAt: h.Reach.At.UTC().Format(time.RFC3339)}
	}
	return connect.NewResponse(out), nil
}

// OfferAddress puts a hold back after a restart, with the ticket's expiry
// and collected state. A hold that exists stays as it is, except that a
// set-up ticket replaces a PREVIEW hold of any target, as RunSetup does.
func (s *Server) OfferAddress(_ context.Context, r *connect.Request[connectv1.OfferAddressRequest]) (*connect.Response[connectv1.OfferAddressResponse], error) {
	t, err := s.fromTicket(r.Msg.GetTicket())
	if err != nil {
		return nil, err
	}
	if h, ok := s.live(t.SetupID); !ok || (t.Phase == PhaseSetUp && h.Phase == PhasePreview) {
		s.put(t)
	}
	state := stateHeld
	if t.CollectedAt != nil {
		state = stateCollected
	}
	return connect.NewResponse(&connectv1.OfferAddressResponse{State: state}), nil
}
