package mcpserver

import (
	"encoding/json"
)

// ErrCodeRestarting answers a request the engine did not run because it is
// restarting onto an upgraded binary (CONTRACT.md, Next steps, Engine
// restarts). Nothing was run for it, so the shim sends it again, once, to
// the engine that comes back.
const ErrCodeRestarting = -32003

// RestartingMessage is the message of ErrCodeRestarting, for a client whose
// shim passes it on.
const RestartingMessage = "the basalt engine is restarting onto the upgraded basalt binary and did not run this call. " +
	"Nothing was run for it: call again in a few seconds"

// Gate admits the requests a server runs. Begin is called before each
// request (not a notification) and false means the request is answered with
// ErrCodeRestarting and not run; End is called after each admitted request
// is answered.
type Gate interface {
	Begin() bool
	End()
}

// openGate admits every request.
type openGate struct{}

func (openGate) Begin() bool { return true }
func (openGate) End()        {}

// Restarting reports whether line is an answer with ErrCodeRestarting, and
// its id in the canonical JSON spelling.
func Restarting(line []byte) (id string, ok bool) {
	var r struct {
		ID    json.RawMessage `json:"id"`
		Error *RPCError       `json:"error"`
	}
	if json.Unmarshal(line, &r) != nil || r.Error == nil || r.Error.Code != ErrCodeRestarting {
		return "", false
	}
	var v any
	if json.Unmarshal(r.ID, &v) != nil || v == nil {
		return "", false
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(raw), true
}
