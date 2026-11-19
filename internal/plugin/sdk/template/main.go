// Command template is the smallest plugin that passes `basalt plugin check`:
// copy this file, change the name and version, and add what your plugin does.
//
// It implements no hook. The SDK has no interface for a hook until that hook's
// messages exist, and a manifest must declare at least one hook, so the
// template declares one with sdk.WithHooks to match the manifest below. When you implement a hook interface, delete the
// WithHooks line: the SDK then declares exactly the hooks your plugin
// implements.
//
// The manifest that goes with it (basalt-plugin.json, next to the binary):
//
//	{
//	  "manifestVersion": 1, "name": "hello-feed", "version": "0.1.0", "publisher": "You",
//	  "protocol": ["basalt-plugin/1"],
//	  "hooks": { "feed.observe": { "contract": "feed/1" } },
//	  "endpoint": { "local": { "transport": "jsonrpc-stdio", "command": "bin/hello-feed" } },
//	  "files": { "bin/hello-feed": "sha256:<hash of the binary>" },
//	  "network": { "egress": [] }
//	}
//
// To serve another transport, change endpoint.local.transport to jsonrpc-unix
// or connectrpc and add "args": ["-transport", "<the same name>"]. The binary
// reads that flag; the engine starts it with the arguments the manifest names
// and with SocketEnv set for a socket transport.
//
// Write nothing to stdout: with jsonrpc-stdio it is the protocol's stream.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/plugin/sdk"
)

// plugin is all an author must write to be served: a name and a version.
type plugin struct{}

func (plugin) Info() sdk.Info {
	return sdk.Info{Name: "hello-feed", Version: "0.1.0"}
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("hello-feed", flag.ContinueOnError)
	transport := fs.String("transport", "", "jsonrpc-stdio, jsonrpc-unix or connectrpc (default: from the environment)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := []sdk.Option{
		// Delete this once the plugin implements a hook interface.
		sdk.WithHooks(map[string]sdk.HookDecl{"feed.observe": {Contract: "feed/1"}}),
	}
	if *transport != "" {
		opts = append(opts, sdk.WithTransport(sdk.Transport(*transport)))
	}
	if err := sdk.Serve(ctx, plugin{}, opts...); err != nil {
		fmt.Fprintln(os.Stderr, "hello-feed:", err)
		return 1
	}
	return 0
}
