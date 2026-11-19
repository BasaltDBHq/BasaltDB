// Package sdk serves a Basalt plugin. A plugin author writes what the plugin
// does; the SDK speaks the protocol.
//
// The SDK answers initialize (with version negotiation), health and shutdown,
// enforces the 4 MiB message cap in both directions, applies the entry's
// per-call deadline to the context of every call, keeps at most four hook
// calls running at once (health and shutdown are answered beside them), and exits cleanly on shutdown. It never logs, never reads
// the environment beyond SocketEnv, and puts no value from a message in any
// error.
//
// # From zero to a served plugin
//
// A plugin is a type with an Info method. Every manifest lists at least one
// hook, and the engine refuses a plugin that does not declare the hooks its
// manifest lists, so until the SDK has an interface for the hook you want,
// declare it with WithHooks:
//
//	type plugin struct{}
//
//	func (plugin) Info() sdk.Info { return sdk.Info{Name: "hello-feed", Version: "0.1.0"} }
//
//	func main() {
//		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
//		defer stop()
//		hooks := sdk.WithHooks(map[string]sdk.HookDecl{"feed.observe": {Contract: "feed/1"}})
//		if err := sdk.Serve(ctx, plugin{}, hooks); err != nil {
//			fmt.Fprintln(os.Stderr, err)
//			os.Exit(1)
//		}
//	}
//
// The template (directory template, package main) is this program with a
// transport flag and the manifest it needs. The SDK lives inside the engine's
// module until it moves to its own repository, so build the template from a
// clone of the engine, and expect the import path to change when the SDK
// moves. The steps below are the ones the engine's own test runs, in
// same-user mode: engine.json has "mode": "SAME_USER" and lists the agent you
// pass to --agents, and trust, add and enable ask for a yes at the prompt.
//
//  1. Build it, from the engine's module:
//     go build -o hello-feed/bin/hello-feed ./internal/plugin/sdk/template
//  2. Write hello-feed/basalt-plugin.json. The template's comment has a
//     manifest to start from. Its "files" entry holds the binary's SHA-256
//     (shasum -a 256 hello-feed/bin/hello-feed), and its name, version and
//     hooks must equal what Info and the declared hooks say, or the engine
//     refuses the plugin at initialize.
//  3. Make a key and sign: basalt plugin keygen --out KEYDIR, then
//     basalt plugin sign hello-feed --key KEYDIR/KEYID.key.
//  4. Trust your key on your own engine: basalt plugin trust KEYDIR/KEYID.pub.
//  5. Install and turn it on, for the agents it should serve:
//     basalt plugin add hello-feed --agents product_a, then
//     basalt plugin enable hello-feed.
//  6. Check it: basalt plugin check hello-feed. It starts the plugin, runs
//     initialize and health, and sends shutdown. It prints
//     "plugin hello-feed/default: initialize 3ms, health READY 1ms".
//
// In same-user mode (the foreground engine, for development and CI) all of this
// runs as your user under the engine's config directory.
//
// # Choosing a transport
//
// The author writes no transport code. The manifest's endpoint.local.transport
// says how the engine starts and reaches the plugin, and Serve follows:
//
//   - jsonrpc-stdio: the default when SocketEnv is not set. The engine speaks
//     JSON-RPC on the plugin's stdin and stdout. Write nothing else to stdout.
//   - jsonrpc-unix: the default when SocketEnv is set. The engine starts the
//     plugin with that one environment variable, the absolute path of a socket;
//     Serve listens on it.
//   - connectrpc: pass WithTransport(ConnectRPC). With SocketEnv set, Serve
//     serves ConnectRPC and gRPC over h2c on that socket, so a plain gRPC
//     client works too.
//
// One binary can serve all three: read a flag, put it in the manifest's "args",
// and pass sdk.WithTransport(sdk.Transport(flagValue)), as the template does.
//
// A remote plugin (the manifest's endpoint.remote) serves ConnectRPC on a
// listener the author supplies, over TLS:
//
//	l, err := tls.Listen("tcp", ":8443", &tls.Config{Certificates: certs})
//	...
//	sdk.Serve(ctx, p, sdk.WithListener(l, tlsConfig), sdk.WithBearerToken(token))
//
// The engine requires TLS and checks the certificate against the endpoint's
// host. WithBearerToken makes the server require the "Authorization: Bearer"
// header the engine sends when the entry has a credential file.
//
// # Optional behavior
//
// Plugin has one method. The SDK looks for more with type assertions, so a
// plugin implements only what it needs:
//
//   - Initializer receives the entry's config and limits at initialize.
//   - HealthChecker reports NOT_READY when it returns an error.
//   - Shutdowner runs before the shutdown reply, to flush or release.
//
// Handlers receive a context that ends at the call's deadline and must return
// when it does. A hook handler that does not keeps its slot until it returns:
// a later hook call waits for a slot until its own deadline and is then
// answered deadline exceeded, and health and shutdown are still answered.
//
// # Hooks
//
// A plugin extends Basalt through hooks. Each hook's messages land with that
// hook's own work, and each will add one optional interface here (found the
// same way, by type assertion) with typed payloads. The SDK declares a hook in
// initialize only for a plugin that implements its interface, so adding a hook
// to the SDK never changes a plugin written before it. No hook interface
// exists yet. A manifest must still declare one hook, so until the interface
// for yours exists, declare it with WithHooks, as the template does. How a
// hook is added to the SDK is described on hookSpec.
package sdk
