package guidance

import "time"

// TrustStatus is status.trust.
type TrustStatus struct {
	Host string `json:"host"`
	// Applies is PROFILE, SSLROOTCERT, SYSTEM or NOT_VERIFIED.
	Applies string `json:"applies"`
	// Profile and Origin name the profile when Applies is PROFILE.
	Profile string `json:"profile,omitempty"`
	Origin  string `json:"origin,omitempty"`
	// Verify is CA for a pin that checks the chain against its own root
	// without the host name; absent for a full check.
	Verify string `json:"verify,omitempty"`
	// RootCount is how many roots the profile holds; Roots lists up to 8,
	// those that expire first.
	RootCount int               `json:"rootCount,omitempty"`
	Roots     []TrustRootStatus `json:"roots,omitempty"`
}

// TrustRootStatus is one root of status.trust.roots.
type TrustRootStatus struct {
	Subject  string    `json:"subject"`
	SHA256   string    `json:"sha256"`
	NotAfter time.Time `json:"notAfter"`
}
