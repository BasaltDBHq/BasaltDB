package plugin

import (
	"bytes"
	"encoding/json"
)

// SignerState is who vouches for a copy (CONTRACT.md, Plugins, Plugin
// approval, Signer states).
type SignerState string

// The signer states.
const (
	// SignerKnown: the manifest's .sig names a publisher key built into the
	// engine, passes its schema and verifies. Verified.SignerKeyID is that
	// key's id.
	SignerKnown SignerState = "KNOWN"
	// SignerUnknown: everything else. With RequireApproval that is no .sig,
	// a .sig that fails its schema, or one naming a key the engine does not
	// have built in, and Verified.SignerKeyID is empty: such a key id cannot
	// be checked and could be made up. Without it, the copy was signed by a
	// key from the person's trust store, whose id SignerKeyID holds.
	SignerUnknown SignerState = "UNKNOWN"
)

// Option changes how Stage, Install and Verify check a copy.
type Option func(*options)

type options struct {
	requireApproval bool
}

// RequireApproval checks the copy of an entry that requires approval when
// required is true: the copy is accepted with no known signer, because the
// person's passkey approval decides, and the trust store does not make a
// publisher known. Every other check is unchanged: the path rule (the trust
// store's included), the manifest's hash against the entry's, the manifest's
// rules, the file hashes and the copy's contents. A .sig that names a
// built-in key must still pass its schema and verify. Without it, or with
// required false, a copy must be signed by a trusted key, as before.
func RequireApproval(required bool) Option {
	return func(o *options) { o.requireApproval = required }
}

func optionsOf(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// signerOf works out a copy's signer from the manifest's exact bytes and
// its .sig (raw, when signed is true). Refusals name sigPath.
//
// Without approval the .sig must name a trusted key and verify, as before;
// the state is KNOWN when that key is built in.
//
// With approval only the built-in keys count. A .sig that names one must
// pass its schema and verify, or it is refused: that is damage or
// tampering. Anything else is UNKNOWN with no key id, and the trust store is
// not read for it.
func signerOf(sigPath string, manifest, raw []byte, signed bool, trust TrustStore, o options) (SignerState, string, error) {
	if !o.requireApproval {
		keyID, err := checkSignature(sigPath, manifest, raw, trust)
		if err != nil {
			return "", "", err
		}
		if _, ok := trust.embedded[keyID]; ok {
			return SignerKnown, keyID, nil
		}
		return SignerUnknown, keyID, nil
	}
	if !signed {
		return SignerUnknown, "", nil
	}
	keyID, sig, err := parseSignatureFile(raw)
	if err != nil {
		if namesBuiltInKey(raw, trust) {
			return "", "", inFile(err, sigPath)
		}
		return SignerUnknown, "", nil
	}
	pub, ok := trust.embedded[keyID]
	if !ok {
		return SignerUnknown, "", nil
	}
	if !verifyManifestSig(pub, manifest, sig) {
		return "", "", &VerifyError{Reason: RefusedNotTrusted, File: sigPath, Why: "the signature does not verify over the manifest"}
	}
	return SignerKnown, keyID, nil
}

// namesBuiltInKey reports whether a .sig that fails its schema still names
// a built-in key: its bytes hold the key's id, or any JSON string in it
// decodes to the id (an escaped character, a repeated key). Such a .sig is
// refused rather than taken as unsigned.
func namesBuiltInKey(raw []byte, trust TrustStore) bool {
	for id := range trust.embedded {
		if bytes.Contains(raw, []byte(id)) {
			return true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if s, ok := tok.(string); ok {
			if _, builtIn := trust.embedded[s]; builtIn {
				return true
			}
		}
	}
}
