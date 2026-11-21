// The portal's approval and revert page code (web/lib: relay.js over
// channel.js, local.js, codec.js, page.js), driven step by step by
// relay_pages_internal_test.go against a real engine through the Go fake
// Vault. The test stands in for the browser's passkey prompt: the page code
// says what to sign, the test signs it with a software P-256 passkey and
// hands the assertion back, as navigator.credentials.get would.
//
// Argument: the fake Vault's ws:// base URL. Then one JSON command per line
// on stdin, one JSON answer per line on stdout:
//
//   { op: "open", secret }                    the RELAY session for a short link
//   { op: "read", kind, id, secret }          fetchRequest and the page's check;
//                                             answers what the passkey signs
//   { op: "sign", kind, id, secret, assertion }  the page's response JSON, posted
//                                             as finish() does; answers the
//                                             result and the receipt line
//   { op: "request", method, path, secret, body }  one raw request in the session
//   { op: "close" }
//
// It never prints a secret.
import { createInterface } from "node:readline";

import { approvalResponseJSON, b64urlDecode, b64urlEncode, checkApprovalRequest, checkRevertRequest, revertResponseJSON } from "../../../web/lib/codec.js";
import { fetchRequest, postResponse, relayPaths, revertPaths } from "../../../web/lib/local.js";
import { receiptLine } from "../../../web/lib/page.js";
import { RELAY_ORIGIN, relayTransport } from "../../../web/lib/relay.js";

const [vaultURL] = process.argv.slice(2);
const out = (v) => process.stdout.write(JSON.stringify(v) + "\n");
const failure = (err) => ({ error: { name: err?.name ?? "", code: err?.code ?? "", reason: err?.reason ?? "", status: err?.status ?? 0, message: err?.message ?? String(err) } });

const transport = relayTransport({
  socket: (url) => {
    if (!url.startsWith(RELAY_ORIGIN + "/")) throw new Error("a socket outside the Vault");
    return new WebSocket(vaultURL + url.slice(RELAY_ORIGIN.length), { headers: { origin: "https://portal.basaltvault.app" } });
  },
  pageHide: () => {},
});

let session = null;
const noWait = async () => {};

const pages = {
  approvals: { check: checkApprovalRequest, json: approvalResponseJSON, idField: "approvalId", paths: (id) => relayPaths("approvals", id) },
  reverts: { check: checkRevertRequest, json: revertResponseJSON, idField: "revertId", paths: (id) => revertPaths(id) },
};

async function run(c) {
  switch (c.op) {
    case "open":
      session = await transport.open({ page: "approvals", id: "", secret: c.secret });
      return { engine: { engineId: session.engine.engineId, fingerprint: session.engine.fingerprint } };
    case "read": {
      const p = pages[c.kind];
      const req = await p.check(await fetchRequest(session, p.paths(c.id).request, c.secret, noWait));
      return { id: req[p.idField], challenge: b64urlEncode(req.challenge), credentialIds: req.credentialIds.map((b) => b64urlEncode(b)), rows: req.binding?.rows ?? null };
    }
    case "sign": {
      const p = pages[c.kind];
      const a = c.assertion;
      const response = {
        [p.idField]: c.id,
        credentialId: b64urlDecode(a.credentialId),
        authenticatorData: b64urlDecode(a.authenticatorData),
        clientDataJson: b64urlDecode(a.clientDataJson),
        signature: b64urlDecode(a.signature),
      };
      const result = await postResponse(session, p.paths(c.id).relay, c.secret, p.json(response));
      return { result, receiptLine: await receiptLine(result, session) };
    }
    case "request": {
      const headers = { "basalt-link-secret": c.secret };
      if (c.method === "POST") headers["content-type"] = "application/json";
      const res = await session.request(c.method, c.path, headers, c.body ?? null);
      return { status: res.status, body: res.body, ended: session.channel?.ended?.code ?? "" };
    }
    case "state":
      return { ended: session.channel?.ended?.code ?? "", closed: session.closed };
    case "close":
      session?.close();
      return {};
    default:
      throw new Error(`unknown op ${c.op}`);
  }
}

const lines = createInterface({ input: process.stdin });
for await (const line of lines) {
  const c = JSON.parse(line);
  try {
    out({ op: c.op, ...(await run(c)) });
  } catch (err) {
    out({ op: c.op, ...failure(err) });
  }
  if (c.op === "close") break;
}
session?.close();
process.exit(0);
