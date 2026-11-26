package vault

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// Gate counts the requests running, so a restart onto an upgraded binary
// waits for them; Begin is false once it is closed.
type Gate interface {
	Begin() bool
	End()
}

// GatedDispatcher counts each page-session request (an approval or a
// revert relayed through the Vault) in Gate, and answers UNAVAILABLE with
// nothing run once the gate is closed.
type GatedDispatcher struct {
	Gate Gate
	Next Dispatcher
}

// Dispatch implements Dispatcher.
func (d GatedDispatcher) Dispatch(ctx context.Context, link SessionLink, req Request) Response {
	if !d.Gate.Begin() {
		return restartingResponse()
	}
	defer d.Gate.End()
	return d.Next.Dispatch(ctx, link, req)
}

// restartingResponse is the pages API's error for a request the engine did
// not run because it is restarting.
func restartingResponse() Response {
	body, err := json.Marshal(map[string]string{
		"code":    guidance.CodeUnavailable,
		"message": "the basalt engine is restarting onto the upgraded binary and did not run this request; nothing was run: try again in a few seconds",
	})
	if err != nil {
		panic(err) // a map of strings
	}
	return Response{Status: http.StatusServiceUnavailable, ContentType: "application/json", Body: body}
}
