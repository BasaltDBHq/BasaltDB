package app

import (
	"crypto/x509"

	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
)

// trustPins is the config's trust.d as the hand-off writes its pins
// (handoff.TrustPins).
type trustPins struct{}

func (trustPins) PinNew(configPath, host string, cert *x509.Certificate, caOnly bool) (bool, error) {
	return trustdir.PinNew(configPath, host, cert, caOnly)
}

func (trustPins) Repin(configPath, host string, cert *x509.Certificate, caOnly bool) ([]string, error) {
	return trustdir.Repin(configPath, host, cert, caOnly)
}
