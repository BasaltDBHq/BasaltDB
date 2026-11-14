// The portal page's DIRECT transport (web/lib/direct.js over
// web/lib/channel.js) against a Go engine's direct listener, run by
// direct_page_test.go. Arguments: the session URL (ws://127.0.0.1:<port>/v1/session),
// then a JSON object { secret, engineKey, engineId, item, pinnedId }.
// It prints one JSON line per step.
import { directTransport } from "../../../web/lib/direct.js";

const [url, raw] = process.argv.slice(2);
const a = JSON.parse(raw);
const address = "https://engine.example.com";
const pins = [{ address, engineKey: a.engineKey, engineId: a.pinnedId, addedAt: "2026-11-14T10:00:00Z", lastUsedAt: null }];
const store = { list: () => pins, touch: () => {}, inCookie: () => true, syncCookie: () => {} };
const sockets = [];
const transport = directTransport({
  store,
  // The probe answers as the engine's /v1/engine would; the session goes to
  // the test listener whatever the pinned host.
  fetchFn: async () => new Response(JSON.stringify({ engineKey: a.engineKey, engineId: a.engineId }), { status: 200 }),
  socket: (u) => {
    sockets.push(u);
    return new WebSocket(url);
  },
});

const out = (v) => process.stdout.write(JSON.stringify(v) + "\n");
const SECRET = "basalt-link-secret";
try {
  const session = await transport.open({ page: "approvals", id: a.item, secret: a.secret });
  out({ step: "open", socket: sockets[0], engine: session.engine });
  const get = await session.request("GET", `/api/v1/approvals/${a.item}`, { [SECRET]: a.secret });
  out({ step: "get", status: get.status, body: JSON.parse(get.body) });
  const body = JSON.stringify({ pad: "é\"\n€".repeat(1500) });
  const post = await session.request("POST", `/api/v1/approvals/${a.item}/approve`, { [SECRET]: a.secret, "content-type": "application/json" }, body);
  out({ step: "post", status: post.status, body: JSON.parse(post.body), sent: body.length });
  const big = await session.request("GET", "/big", { [SECRET]: a.secret });
  out({ step: "big", status: big.status, length: big.body.length, type: big.headers["content-type"] });
  session.close();
} catch (err) {
  out({ step: "error", code: err.code ?? "", reason: err.reason ?? "", message: err.message, personMessage: err.personMessage ?? "" });
}
