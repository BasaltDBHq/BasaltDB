package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	basaltplugin "github.com/basaltdbhq/basalt-plugin-go"

	tn "github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/testnotifier"
)

// serveRaw speaks JSON-RPC without the SDK, for the modes whose answers the
// SDK refuses to send: a lastSeq that is no seq of the batch, and a line that
// is not JSON. It serves stdin and stdout, or the socket in basaltplugin.SocketEnv
// when it is set, until shutdown or the end of the stream.
func serveRaw(ctx context.Context, n *notifier, m tn.Mode, feed, deliver bool) error {
	hooks := map[string]map[string]string{}
	if feed {
		hooks[tn.HookFeedObserve] = map[string]string{"contract": basaltplugin.ContractFeed}
	}
	if deliver {
		hooks[tn.HookApprovalDeliver] = map[string]string{"contract": basaltplugin.ContractDeliver}
	}
	r := &raw{n: n, mode: m, hooks: hooks}
	path := os.Getenv(basaltplugin.SocketEnv)
	if path == "" {
		r.serve(os.Stdin, os.Stdout)
		return nil
	}
	if !filepath.IsAbs(path) {
		return errors.New("the socket path is not absolute")
	}
	// A socket a crash left at the path is removed first, as the SDK does.
	if fi, err := os.Lstat(path); err == nil && fi.Mode().Type() == os.ModeSocket {
		_ = os.Remove(path)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return nil // stopping: ctx closed the listener
		}
		if err != nil {
			return err
		}
		go r.serve(c, c)
	}
}

type raw struct {
	n     *notifier
	mode  tn.Mode
	hooks map[string]map[string]string
}

type rawRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

func (r *raw) serve(in io.Reader, out io.Writer) {
	var mu sync.Mutex
	write := func(b []byte) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = out.Write(append(b, '\n'))
	}
	reply := func(id json.RawMessage, result any) {
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
		if err == nil {
			write(b)
		}
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20+1)
	for sc.Scan() {
		var req rawRequest
		if json.Unmarshal(sc.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue // not a request, or a notification: nothing to answer
		}
		switch req.Method {
		case "initialize":
			reply(req.ID, map[string]any{"protocol": basaltplugin.Protocol, "name": tn.Name, "version": tn.Version, "hooks": r.hooks})
		case "health":
			reply(req.ID, map[string]string{"status": "READY"})
		case "shutdown":
			reply(req.ID, map[string]any{})
			os.Exit(0)
		case tn.HookFeedObserve:
			var p struct {
				Agent  string            `json:"agent"`
				Events []json.RawMessage `json:"events"`
			}
			_ = json.Unmarshal(req.Params, &p)
			r.n.rec.write(tn.Record{Hook: req.Method, Agent: p.Agent, Mode: r.mode, Events: p.Events})
			if r.mode == tn.ModeBadJSON {
				write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"lastSeq":`))
				continue
			}
			reply(req.ID, map[string]int64{"lastSeq": lastSeq(p.Events) + 1})
		case tn.HookApprovalDeliver:
			var p struct {
				Event json.RawMessage `json:"event"`
			}
			_ = json.Unmarshal(req.Params, &p)
			// The notice's own data.agent, as the SDK path records it.
			var notice struct {
				Data struct {
					Agent string `json:"agent"`
				} `json:"data"`
			}
			_ = json.Unmarshal(p.Event, &notice)
			r.n.rec.write(tn.Record{Hook: req.Method, Agent: notice.Data.Agent, Mode: r.mode, Event: p.Event})
			if r.mode == tn.ModeBadJSON {
				write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":`))
				continue
			}
			reply(req.ID, map[string]any{})
		default:
			b := []byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32601,"message":"method not found"}}`)
			write(b)
		}
	}
}

// lastSeq is the data.seq of a batch's last event.
func lastSeq(events []json.RawMessage) int64 {
	if len(events) == 0 {
		return 0
	}
	var e struct {
		Data struct {
			Seq json.Number `json:"seq"`
		} `json:"data"`
	}
	_ = json.Unmarshal(events[len(events)-1], &e)
	n, _ := strconv.ParseInt(string(e.Data.Seq), 10, 64)
	return n
}
