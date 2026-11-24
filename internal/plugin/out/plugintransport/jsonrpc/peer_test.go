package jsonrpc_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginproto"
	"github.com/basaltdbhq/basaltdb/internal/plugin/out/plugintransport/adaptertest"
)

// The test binary doubles as the plugin: TestMain runs peerMain when the
// first argument is peerFlag. The child gets an empty environment, so
// everything it needs comes in through its arguments.

const (
	peerFlag   = "--peer"
	peerExit   = 3
	peerJitter = 3 * time.Millisecond
	floodBytes = 8 << 20
)

// peerArgs builds the arguments of a peer: its mode, then key=value options.
func peerArgs(mode string, opts ...string) []string {
	return append([]string{peerFlag, mode}, opts...)
}

func modeOf(b adaptertest.Behavior) string {
	switch b {
	case adaptertest.Oversized:
		return "oversized"
	case adaptertest.Garbage:
		return "garbage"
	case adaptertest.ExitOnCall:
		return "exit"
	case adaptertest.Hang:
		return "hang"
	case adaptertest.Echo:
		return "echo"
	}
	panic("unknown behavior")
}

type peerRequest struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// peerMain never returns.
func peerMain(args []string) {
	mode := args[0]
	opts := map[string]string{}
	for _, a := range args[1:] {
		k, v, _ := strings.Cut(a, "=")
		opts[k] = v
	}
	if sock := opts["socket"]; sock != "" {
		l, err := net.Listen("unix", sock)
		if err != nil {
			os.Exit(1)
		}
		for {
			c, err := l.Accept()
			if err != nil {
				os.Exit(1)
			}
			go serve(c, c, mode, opts)
		}
	}
	serve(os.Stdin, os.Stdout, mode, opts)
	os.Exit(0)
}

func serve(r io.Reader, w io.Writer, mode string, opts map[string]string) {
	var wmu sync.Mutex
	write := func(b []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		_, _ = w.Write(b)
	}
	reply := func(id json.RawMessage, result []byte) {
		var b bytes.Buffer
		fmt.Fprintf(&b, `{"jsonrpc":"2.0","id":%s,"result":`, id)
		b.Write(result)
		b.WriteString("}\n")
		write(b.Bytes())
	}

	br := bufio.NewReaderSize(r, pluginproto.MaxMessageBytes+2)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		var req peerRequest
		if json.Unmarshal(line, &req) != nil {
			return
		}
		params := req.Params
		if len(params) == 0 {
			params = []byte("{}")
		}
		switch mode {
		case "echo":
			go func() {
				time.Sleep(rand.N(peerJitter))
				reply(req.ID, params)
			}()
		case "slow":
			ms, _ := strconv.Atoi(opts["ms"])
			go func() {
				time.Sleep(time.Duration(ms) * time.Millisecond)
				reply(req.ID, params)
			}()
		case "hang":
		case "exit":
			os.Exit(peerExit)
		case "garbage":
			write([]byte(adaptertest.GarbageMarker + " this is not json\n"))
		case "oversized":
			writeLine(write, req.ID, pluginproto.MaxMessageBytes+1000)
		case "size":
			n, _ := strconv.Atoi(opts["n"])
			writeLine(write, req.ID, n)
		case "flood":
			write(bytes.Repeat([]byte("a"), floodBytes))
		case "rpcerror":
			write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"error":{"code":-32000,"message":"` + adaptertest.GarbageMarker + `"}}` + "\n"))
		case "noresult":
			write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + "}\n"))
		case "wrongtype":
			reply(req.ID, []byte(`{"n":"not a number"}`))
		case "strangeid":
			write([]byte(`{"jsonrpc":"2.0","id":987654,"result":{}}` + "\n"))
		case "env":
			b, err := json.Marshal(struct {
				Env []string `json:"env"`
			}{os.Environ()})
			if err != nil {
				os.Exit(1)
			}
			reply(req.ID, b)
		case "rawparams":
			// The params' bytes as they came off the line, as a string.
			b, err := json.Marshal(struct {
				Raw string `json:"raw"`
			}{string(params)})
			if err != nil {
				os.Exit(1)
			}
			reply(req.ID, b)
		case "pid":
			reply(req.ID, []byte(`{"pid":`+strconv.Itoa(os.Getpid())+`}`))
		case "stderr":
			fmt.Fprintln(os.Stderr, adaptertest.GarbageMarker)
			reply(req.ID, params)
		}
	}
}

// writeLine writes one response line of exactly n bytes, newline excluded.
func writeLine(write func([]byte), id json.RawMessage, n int) {
	head := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"s":"`, id)
	tail := `"}}`
	pad := n - len(head) - len(tail)
	if pad < 0 {
		pad = 0
	}
	var b bytes.Buffer
	b.WriteString(head)
	b.Write(bytes.Repeat([]byte("a"), pad))
	b.WriteString(tail)
	b.WriteByte('\n')
	write(b.Bytes())
}
