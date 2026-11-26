//go:build providerroots

package trustprofile

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestProviderRootsCurrent downloads each built-in profile's source, one
// per roots file, and compares what it publishes (the file itself, or for a
// file published inside source code, such as Supabase's 2025 root in its
// CLI, the PEM text in that code) with the embedded file and its pinned
// SHA-256. It needs the network, so it runs only from make
// check-provider-roots, never in CI. A failure means the provider changed
// its roots: fetch the URL it names, check what changed (new roots only,
// from the provider), replace the file under profiles/, and update its
// sha256 in the profile and its pin and count in builtin_test.go.
func TestProviderRootsCurrent(t *testing.T) {
	client := &http.Client{Timeout: 30 * time.Second}
	for _, p := range BuiltIns() {
		if len(p.Source) != len(p.Files) {
			t.Errorf("%s: %d sources for %d roots files", p.Name, len(p.Source), len(p.Files))
			continue
		}
		for _, f := range p.Files {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.Source, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s: %v", f.Name, err)
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, MaxRootFileBytes*4))
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: status %d, %v", f.Name, resp.StatusCode, err)
			}
			body = published(body)
			got := FileSHA256(body)
			if got != f.SHA256 || !bytes.Equal(body, f.PEM) {
				t.Errorf("%s/%s: %s now gives SHA-256 %s, pinned %s", p.Name, f.Name, f.Source, got, f.SHA256)
				continue
			}
			t.Logf("%s/%s: %s matches the pinned SHA-256 %s", p.Name, f.Name, f.Source, got)
		}
	}
}
