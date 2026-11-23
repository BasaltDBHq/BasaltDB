package pages_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

const revealBody = `{"proof":{"credentialId":"AQ","authenticatorData":"Ag","clientDataJson":"Aw","signature":"BA"},"revealSecret":"AAECAwQFBgcICQoLDA0ODw"}`

// POST …/reveal: the link's secret first, then the relay's origin, type
// and size checks, a strict body, and the answer never cached.
func TestPagesRevealRoute(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	a := &stubAgent{known: id}
	s := serve(t, a)
	host := strings.TrimPrefix(s.origin, "http://")
	path := "/api/v1/approvals/" + id.String() + "/reveal"
	secret, err := s.secrets.Issue(id, time.Now().Add(time.Hour))
	require.NoError(t, err)

	status, _ := s.do(t, http.MethodPost, path, host, s.origin, "application/json", revealBody, "wrong")
	require.Equal(t, http.StatusNotFound, status, "a wrong link secret reads as an unknown id")
	status, _ = s.do(t, http.MethodPost, path, host, "", "application/json", revealBody, secret)
	require.Equal(t, http.StatusForbidden, status)
	status, _ = s.do(t, http.MethodPost, path, host, s.origin, "text/plain", revealBody, secret)
	require.Equal(t, http.StatusUnsupportedMediaType, status)
	status, _ = s.do(t, http.MethodPost, path, host, s.origin, "application/json", `{"x":"`+strings.Repeat("x", 20<<10)+`"}`, secret)
	require.Equal(t, http.StatusRequestEntityTooLarge, status)
	for name, body := range map[string]string{
		"an unknown key":       strings.Replace(revealBody, `"revealSecret"`, `"ticket":"x","revealSecret"`, 1),
		"no reveal secret":     `{"proof":{"credentialId":"AQ","authenticatorData":"Ag","clientDataJson":"Aw","signature":"BA"}}`,
		"a proof without data": `{"proof":{"credentialId":"AQ"},"revealSecret":"AAECAwQFBgcICQoLDA0ODw"}`,
		"two values":           revealBody + revealBody,
	} {
		status, out := s.do(t, http.MethodPost, path, host, s.origin, "application/json", body, secret)
		require.Equal(t, http.StatusBadRequest, status, name+": "+out)
	}
	require.Empty(t, a.revealed)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.base+path, strings.NewReader(revealBody))
	require.NoError(t, err)
	req.Host = host
	req.Header.Set("Origin", s.origin)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(links.SecretHeader, secret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	require.JSONEq(t, `{"rows":[{"line":1,"row":"[{\"id\": 9}, {\"id\": 9}, null]"}]}`, string(raw))
	require.Len(t, a.revealed, 1)

	a.err = &toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Reason: "REVEAL_REFUSED", Message: "refused"}
	status, out := s.do(t, http.MethodPost, path, host, s.origin, "application/json", revealBody, secret)
	require.Equal(t, http.StatusConflict, status)
	require.Contains(t, out, `"reason":"REVEAL_REFUSED"`)
}
