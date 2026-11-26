package trustprofile

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
)

// pinFingerprintLen is how much of a pinned certificate's fingerprint its
// PEM file's name carries, so a new root gets a new file.
const pinFingerprintLen = 16

// PinFiles is a pin: the exact-host operator profile for one host that
// holds the one certificate a person accepted, and the files that hold it
// in trust.d.
type PinFiles struct {
	Profile *Profile
	// PEMName and PEM are its roots file; JSON is its profile file.
	PEMName   string
	PEM, JSON []byte
}

// NewPin is the pin for host holding cert (pin-<host>, match =host), with
// verify: ca when caOnly (a certificate that does not name the host). It is
// built in memory and written nowhere. Its Parse reads roots.
func NewPin(host string, cert *x509.Certificate, caOnly bool, roots Roots) (PinFiles, error) {
	h := NormalizeHost(host)
	match, err := NormalizeMatch("=" + h)
	if err != nil {
		return PinFiles{}, err
	}
	name := PinName(h)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	pemName := name + "-" + DERSHA256(cert)[:pinFingerprintLen] + ".pem"
	spec := Spec{Name: name, Match: []string{match}, Roots: []RootSpec{{File: pemName, SHA256: FileSHA256(pemBytes)}}}
	if caOnly {
		spec.Verify = VerifyCA
	}
	raw, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return PinFiles{}, err
	}
	raw = append(raw, '\n')
	p, err := Parse(raw, Operator, func(string) ([]byte, error) { return pemBytes, nil }, roots)
	if err != nil {
		return PinFiles{}, err
	}
	return PinFiles{Profile: p, PEMName: pemName, PEM: pemBytes, JSON: raw}, nil
}
