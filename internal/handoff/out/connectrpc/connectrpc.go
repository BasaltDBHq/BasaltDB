// Package connectrpc is the handoff domain's transport to the connect
// service: the generated ConnectRPC client of its SetupService over HTTPS,
// which handoff.Client signs its calls for.
package connectrpc

import (
	"net/http"
	"time"

	"github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1/connectv1connect"
)

// requestTimeout bounds one call when the caller gives no HTTP client.
const requestTimeout = 20 * time.Second

// New is a client of the SetupService at baseURL (handoff.ServiceURL
// outside tests) through httpClient, or a client with requestTimeout when
// httpClient is nil.
func New(httpClient *http.Client, baseURL string) connectv1connect.SetupServiceClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return connectv1connect.NewSetupServiceClient(httpClient, baseURL)
}
