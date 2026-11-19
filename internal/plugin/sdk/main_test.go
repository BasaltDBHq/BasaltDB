package sdk

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

// The test binary doubles as a plugin: TestMain runs peerMain when the first
// argument is peerFlag, so the engine's adapters talk to a real child process
// built from the SDK. The child gets an empty environment except for the
// socket variable a test sets.

const (
	peerFlag = "--peer"
	peerExit = 3
)

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == peerFlag {
		peerMain(os.Args[2])
	}
	goleak.VerifyTestMain(m)
}

type peerPlugin struct{}

func (peerPlugin) Info() Info { return Info{Name: "sdk-peer", Version: "1.0.0"} }

// peerMain never returns. The "echo" method it adds answers as the engine's
// adapter suite expects, in the behavior the mode names.
func peerMain(mode string) {
	switch mode {
	case "notifier", "notifier-connect":
		var opts []Option
		if mode == "notifier-connect" {
			opts = append(opts, WithTransport(ConnectRPC))
		}
		if Serve(context.Background(), notifierPeer{}, opts...) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	extra := map[string]methodFunc{"echo": func(ctx context.Context, params json.RawMessage) (any, *rpcError) {
		switch mode {
		case "oversized":
			return strings.Repeat("x", MaxMessageBytes+1000), nil
		case "hang":
			<-ctx.Done()
			return nil, errDeadline
		case "exit":
			os.Exit(peerExit)
		}
		return params, nil
	}}
	err := Serve(context.Background(), peerPlugin{}, withExtra(extra))
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
