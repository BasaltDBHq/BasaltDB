//go:build providerroots

package providerca

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"
)

// maxRootsFile bounds a download; the RDS bundle is about 175 KB.
const maxRootsFile = 4 << 20

// TestProviderRootsCurrent downloads where each embedded file is published
// and compares it with the embedded copy and its pinned SHA-256: the file
// itself, or for a file published inside source code (Supabase's 2025
// root, in its CLI), the PEM text in that code. It needs the network, so it
// runs only from make check-provider-roots, never in CI. A failure means the
// provider changed its roots: fetch the URL it names, check what changed
// (new roots only, from the provider), replace the embedded file and update
// the pin in providerca.go and the pin and count in pins_test.go.
func TestProviderRootsCurrent(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}
	for _, p := range providers {
		for _, f := range p.files {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", f.path, err)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxRootsFile))
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d, %v", f.path, resp.StatusCode, err)
			}
			if f.inCode {
				body = pemInCode(body)
			}
			sum := sha256.Sum256(body)
			got := hex.EncodeToString(sum[:])
			if got != f.sha256 || !bytes.Equal(body, f.pem) {
				t.Errorf("%s: %s now gives SHA-256 %s, pinned %s", f.path, f.url, got, f.sha256)
				continue
			}
			t.Logf("%s: %s matches the pinned SHA-256 %s", f.path, f.url, got)
		}
	}
}
