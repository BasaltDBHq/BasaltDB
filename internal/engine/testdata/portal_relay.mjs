// The portal page's RELAY transport (web/lib/relay.js over web/lib/channel.js,
// the code the portal serves) against a Go engine through the Go fake Vault,
// run by vault_portal_page_internal_test.go. Arguments: the fake Vault's
// ws:// base URL, then a JSON object { secret, path, gets }. The socket the
// page asks for (wss://relay.basaltvault.app/v1/links/<token>) is opened at
// the fake Vault instead, from the portal's origin. It prints one JSON line
// per step and never prints the secret.
import { relayTransport, RELAY_ORIGIN } from "../../../web/lib/relay.js";

const [vaultURL, raw] = process.argv.slice(2);
const a = JSON.parse(raw);
const out = (v) => process.stdout.write(JSON.stringify(v) + "\n");
const SECRET = "basalt-link-secret";

const transport = relayTransport({
  socket: (url) => {
    out({ step: "socket", url });
    if (!url.startsWith(RELAY_ORIGIN + "/")) throw new Error(`a socket outside the Vault: ${url}`);
    return new WebSocket(vaultURL + url.slice(RELAY_ORIGIN.length), { headers: { origin: "https://portal.basaltvault.app" } });
  },
  pageHide: () => {},
});

let session = null;
try {
  session = await transport.open({ page: "approvals", id: "", secret: a.secret });
  out({ step: "open", engine: session.engine });
  for (let i = 1; i <= a.gets; i++) {
    const res = await session.request("GET", a.path, { [SECRET]: a.secret });
    out({ step: `get${i}`, status: res.status, type: res.headers["content-type"], body: res.body });
  }
} catch (err) {
  out({ step: "error", name: err.name, code: err.code ?? "", reason: err.reason ?? "", personMessage: err.personMessage ?? "" });
} finally {
  session?.close();
}
