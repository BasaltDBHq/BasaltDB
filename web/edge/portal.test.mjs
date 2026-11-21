// The portal's edge function: the connect page's fixed policy, and every
// other path passed through to the static host.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CONNECT_CSP, CONNECT_SERVICE, DEFAULT_CSP, DEFAULT_HEADERS, handle } from "./portal.js";
import { CONNECT_SERVICE as PAGE_SERVICE } from "../lib/connect.js";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const APPROVE_HTML = read("approve/index.html");
const CONNECT_HTML = read("connect/index.html");
const ID = "0199c0de-0000-7000-8000-000000000000";
const BASE = "https://portal.basaltvault.app";

// headersFile parses web/_headers into { path: { name: value } }.
function headersFile() {
  const out = {};
  let at = null;
  for (const line of read("_headers").split("\n")) {
    if (line.trim() === "" || line.startsWith("#")) continue;
    if (!line.startsWith(" ")) {
      at = line.trim();
      out[at] = {};
      continue;
    }
    const i = line.indexOf(":");
    out[at][line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return out;
}

const request = (path, headers = {}) => new Request(`${BASE}${path}`, { headers });

test("the function's default headers are web/_headers' /* block", () => {
  assert.deepEqual({ ...DEFAULT_HEADERS }, headersFile()["/*"]);
  assert.equal(DEFAULT_HEADERS["Content-Security-Policy"], DEFAULT_CSP);
});

test("web/_routes.json runs the function for the connect page only", () => {
  const routes = JSON.parse(read("_routes.json"));
  assert.deepEqual(routes.include, ["/connect", "/connect/"]);
});

test("the approval and revert pages pass through to the static host untouched", async () => {
  for (const path of [`/approvals/${ID}`, `/reverts/${ID}`, "/lib/codec.js"]) {
    const cached = new Response(APPROVE_HTML, { status: 200, headers: { ...DEFAULT_HEADERS, "Content-Type": "text/html", ETag: '"abc"' } });
    const seen = [];
    const req = request(path, { Cookie: "a=1", "If-None-Match": '"abc"' });
    const res = await handle(req, async (r) => {
      seen.push(r);
      return cached;
    });
    assert.equal(res, cached, path);
    assert.equal(seen[0], req, "the request is passed on as it came");
    assert.equal(res.headers.get("Content-Security-Policy"), DEFAULT_CSP);
  }
});

test("the connect page gets its own policy, the same for everyone, never stored", async () => {
  assert.equal(CONNECT_SERVICE, PAGE_SERVICE);
  assert.equal(CONNECT_CSP, DEFAULT_CSP.replace("default-src 'self'; ", `default-src 'self'; connect-src ${CONNECT_SERVICE}; `));
  const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]*)">/.exec(CONNECT_HTML)[1];
  assert.match(meta, new RegExp(`; connect-src ${CONNECT_SERVICE.replace(/[.]/g, "\\.")};`));
  for (const path of ["/connect", "/connect/"]) {
    for (const cookie of [null, "a=1"]) {
      const cached = new Response(CONNECT_HTML, { status: 200, headers: { ...DEFAULT_HEADERS, "Content-Type": "text/html", ETag: '"abc"' } });
      const seen = [];
      const headers = { "If-None-Match": '"abc"', "If-Modified-Since": "Fri, 13 Nov 2026 00:00:00 GMT" };
      if (cookie) headers.Cookie = cookie;
      const res = await handle(request(path, headers), async (req) => {
        seen.push(req);
        return cached;
      });
      assert.equal(res.status, 200);
      assert.equal(seen[0].headers.get("If-None-Match"), null, "never a 304");
      assert.equal(seen[0].headers.get("If-Modified-Since"), null);
      assert.equal(res.headers.get("Content-Security-Policy"), CONNECT_CSP, path);
      assert.equal(res.headers.get("Cache-Control"), "no-store");
      assert.equal(res.headers.get("ETag"), null);
      for (const [k, v] of Object.entries(DEFAULT_HEADERS)) if (k !== "Content-Security-Policy") assert.equal(res.headers.get(k), v);
      assert.equal(await res.text(), CONNECT_HTML, "the page itself is not changed");
      assert.equal(cached.headers.get("Content-Security-Policy"), DEFAULT_CSP, "the asset's answer is not changed in place");
    }
  }
  for (const path of ["/connect/x", "/connectx", "/connect/index.html"]) {
    const res = await handle(request(path), async () => new Response("x", { status: 200, headers: DEFAULT_HEADERS }));
    assert.equal(res.headers.get("Content-Security-Policy"), DEFAULT_CSP, path);
  }
});
