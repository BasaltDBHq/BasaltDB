// The portal's edge function: the per-person connect-src from the pins
// cookie, the strict default for everyone else, and no answer ever served
// to another person.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { CONNECT_CSP, CONNECT_SERVICE, DEFAULT_CSP, DEFAULT_HEADERS, MAX_ORIGINS, PINS_COOKIE, candidateOrigin, cookieOrigins, handle, policyWith, rewriteMeta } from "./portal.js";
import { CONNECT_SERVICE as PAGE_SERVICE } from "../lib/connect.js";
import { PINS_COOKIE as PAGE_COOKIE, pinsCookie } from "../lib/pins.js";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const APPROVE_HTML = read("approve/index.html");
const REVERT_HTML = read("revert/index.html");
const ENGINES_HTML = read("engines/index.html");
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

test("the function's default headers are web/_headers' /* block", () => {
  assert.deepEqual({ ...DEFAULT_HEADERS }, headersFile()["/*"]);
  assert.equal(DEFAULT_HEADERS["Content-Security-Policy"], DEFAULT_CSP);
});

test("the page and the function name the same cookie", () => {
  assert.equal(PINS_COOKIE, PAGE_COOKIE);
  assert.ok(PINS_COOKIE.startsWith("__Host-"));
});

test("only written engine addresses are read from the cookie", () => {
  const c = (v) => `theme=dark; ${PINS_COOKIE}=${v}; other=1`;
  assert.deepEqual(cookieOrigins(c("https://a.example.com|https://b.example.com:8443")), ["https://a.example.com", "https://b.example.com:8443"]);
  assert.deepEqual(cookieOrigins(c("https://a.example.com|https://a.example.com")), ["https://a.example.com"]);
  for (const bad of [
    "https:",
    "*",
    "https://*.example.com",
    "'unsafe-inline'",
    "https://a.example.com/",
    "https://A.example.com",
    "http://a.example.com",
    "wss://a.example.com",
    "https://localhost:8787",
    "https://127.0.0.1",
    "https://portal.basaltvault.app",
    "https://a.example.com%20https://evil.example",
    "data:",
    "'self' https:",
  ]) {
    assert.deepEqual(cookieOrigins(c(bad)), [], bad);
  }
  assert.deepEqual(cookieOrigins(c("https://ok.example.com|*|https://localhost")), ["https://ok.example.com"]);
  const many = Array.from({ length: 12 }, (_, i) => `https://e${i}.example.com`).join("|");
  assert.equal(cookieOrigins(c(many)).length, MAX_ORIGINS);
  assert.deepEqual(cookieOrigins("x__Host-basalt-engines=https://a.example.com"), []);
  assert.deepEqual(cookieOrigins(undefined), []);
  assert.deepEqual(cookieOrigins(c("https://a.example.com|" + "x".repeat(5000))), []);
});

test("a cookie planted by another host adds nothing", () => {
  const mine = `${PINS_COOKIE}=https://a.example.com`;
  // Two of the name (a sibling host's nameless "=__Host-basalt-engines=..."
  // is sent as one more pair): neither is used.
  assert.deepEqual(cookieOrigins(`${PINS_COOKIE}=https://evil.example.com; ${mine}`), []);
  assert.deepEqual(cookieOrigins(`${mine}; ${PINS_COOKIE}=https://evil.example.com`), []);
  assert.deepEqual(cookieOrigins(`${mine}; ${PINS_COOKIE}=`), []);
  // A name that only looks like ours once Unicode or control spaces are
  // stripped is another cookie: browsers apply no __Host- rules to it.
  for (const pad of ["\u00a0", "\u2000", "\u3000", "\ufeff", "\v", "\f", "\u0085"]) {
    assert.deepEqual(cookieOrigins(`${pad}${PINS_COOKIE}=https://evil.example.com`), [], JSON.stringify(pad));
    assert.deepEqual(cookieOrigins(`${PINS_COOKIE}${pad}=https://evil.example.com`), [], JSON.stringify(pad));
    assert.deepEqual(cookieOrigins(`${pad}${PINS_COOKIE}=https://evil.example.com; ${mine}`), ["https://a.example.com"], JSON.stringify(pad));
  }
  // Spaces and tabs around the pair are the header's own.
  assert.deepEqual(cookieOrigins(`theme=dark;\t ${mine} \t`), ["https://a.example.com"]);
  // Quoting, encoding or a value that smuggles a directive is not an address.
  for (const v of ['"https://a.example.com"', "https%3A%2F%2Fa.example.com", "https://a.example.com,https://b.example.com"]) {
    assert.deepEqual(cookieOrigins(`${PINS_COOKIE}=${v}`), [], v);
  }
});

test("a HEAD request gets the same per-person headers and no body", async () => {
  const { next } = asset();
  const res = await handle(new Request(`${BASE}/approvals/${ID}`, { method: "HEAD", headers: { Cookie: `${PINS_COOKIE}=https://a.example.com` } }), next);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Content-Security-Policy"), policyWith(["https://a.example.com", "wss://a.example.com"]));
  assert.equal(res.headers.get("Cache-Control"), "no-store");
  assert.equal(res.headers.get("Vary"), "Cookie");
  assert.equal(await res.text(), "");
});

test("the cookie the page writes is the one the function reads", () => {
  const pins = [
    { address: "https://a.example.com", engineKey: "A".repeat(122), engineId: "a".repeat(22), addedAt: "2026-11-14T10:00:00Z", lastUsedAt: null },
    { address: "https://b.example.com:8443", engineKey: "B".repeat(122), engineId: "b".repeat(22), addedAt: "2026-11-14T09:00:00Z", lastUsedAt: null },
  ];
  const pair = pinsCookie(pins).split(";")[0];
  assert.deepEqual(cookieOrigins(pair).sort(), ["https://a.example.com", "https://b.example.com:8443"]);
});

test("the per-person policy is the default plus connect-src, nothing broader", () => {
  const p = policyWith(["https://a.example.com", "wss://a.example.com"]);
  assert.equal(
    p,
    "default-src 'self'; connect-src wss://relay.basaltvault.app 'self' https://a.example.com wss://a.example.com; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  );
  assert.doesNotMatch(p, /connect-src[^;]*\b(https|wss):(\s|;)/);
});

test("the page's meta CSP gets the same sources, and only its connect-src changes", () => {
  const sources = ["https://a.example.com", "wss://a.example.com"];
  for (const html of [APPROVE_HTML, REVERT_HTML]) {
    const out = rewriteMeta(html, sources);
    assert.match(out, /connect-src 'self' wss:\/\/relay\.basaltvault\.app https:\/\/a\.example\.com wss:\/\/a\.example\.com;/);
    assert.equal(out.replace(" https://a.example.com wss://a.example.com", ""), html);
  }
  const pin = rewriteMeta(ENGINES_HTML, ["https://a.example.com"]);
  assert.match(pin, /connect-src https:\/\/a\.example\.com;/);
  assert.equal(rewriteMeta("<html>no meta</html>", sources), "<html>no meta</html>");
});

test("the pin page's candidate is one written address, or nothing", () => {
  const u = (q) => new URL(`${BASE}/engines/add${q}`);
  assert.equal(candidateOrigin(u("?address=https%3A%2F%2Fengine.example.com")), "https://engine.example.com");
  assert.equal(candidateOrigin(u("?address=https%3A%2F%2Fengine.example.com%2F")), null);
  assert.equal(candidateOrigin(u("?address=https%3A%2F%2Fa.example.com&address=https%3A%2F%2Fb.example.com")), null);
  assert.equal(candidateOrigin(u("?address=https%3A")), null);
  assert.equal(candidateOrigin(u("")), null);
});

// asset is the static host: the page for a path, with its headers, built
// from one shared record each time, as a cache would.
function asset({ delay = 0, seen = [] } = {}) {
  const cached = new Map([
    ["/approvals/", { body: APPROVE_HTML }],
    ["/reverts/", { body: REVERT_HTML }],
    ["/engines/add", { body: ENGINES_HTML }],
  ]);
  const shared = new Headers({ ...DEFAULT_HEADERS, "Content-Type": "text/html; charset=utf-8", ETag: '"abc"' });
  return {
    shared,
    next: async (req) => {
      seen.push(req);
      if (delay) await new Promise((r) => setTimeout(r, Math.random() * delay));
      const path = new URL(req.url).pathname;
      const key = path.startsWith("/approvals/") ? "/approvals/" : path.startsWith("/reverts/") ? "/reverts/" : path;
      const hit = cached.get(key);
      if (!hit) return new Response("not found", { status: 404 });
      return new Response(hit.body, { status: 200, headers: shared });
    },
  };
}

const request = (path, cookie, headers = {}) => new Request(`${BASE}${path}`, { headers: cookie ? { Cookie: `${PINS_COOKIE}=${cookie}`, ...headers } : headers });

test("a person with pins gets them in connect-src, never stored and varying with the cookie", async () => {
  const { next } = asset();
  const res = await handle(request(`/approvals/${ID}`, "https://a.example.com"), next);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("Content-Security-Policy"), policyWith(["https://a.example.com", "wss://a.example.com"]));
  assert.equal(res.headers.get("Cache-Control"), "no-store");
  assert.equal(res.headers.get("Vary"), "Cookie");
  assert.equal(res.headers.get("ETag"), null);
  for (const [k, v] of Object.entries(DEFAULT_HEADERS)) if (k !== "Content-Security-Policy") assert.equal(res.headers.get(k), v);
  assert.match(await res.text(), /connect-src 'self' wss:\/\/relay\.basaltvault\.app https:\/\/a\.example\.com wss:\/\/a\.example\.com;/);
});

test("without a valid pin the strict default is served as it is", async () => {
  const { next } = asset();
  for (const cookie of [null, "", "https:", "https://localhost", "*|'unsafe-eval'"]) {
    const res = await handle(request(`/reverts/${ID}`, cookie), next);
    assert.equal(res.headers.get("Content-Security-Policy"), DEFAULT_CSP, String(cookie));
    assert.equal(res.headers.get("Cache-Control"), "no-store");
    assert.equal(res.headers.get("Vary"), "Cookie");
    assert.equal(await res.text(), REVERT_HTML);
  }
});

test("one person's header is never served to another", async () => {
  const { next, shared } = asset({ delay: 5 });
  const people = [
    { cookie: "https://alice.example.com", own: ["https://alice.example.com"] },
    { cookie: "https://bob.example.net:8443|https://bob2.example.net", own: ["https://bob.example.net:8443", "https://bob2.example.net"] },
    { cookie: null, own: [] },
    { cookie: "https://carol.example.org", own: ["https://carol.example.org"] },
  ];
  const everyone = people.flatMap((p) => p.own);
  // Many requests, interleaved and concurrent, on both session pages.
  const runs = [];
  for (let i = 0; i < 40; i++) {
    const p = people[i % people.length];
    const path = i % 2 ? `/approvals/${ID}` : `/reverts/${ID}`;
    runs.push(handle(request(path, p.cookie), next).then(async (res) => ({ p, res, body: await res.text() })));
  }
  for (const { p, res, body } of await Promise.all(runs)) {
    const csp = res.headers.get("Content-Security-Policy");
    const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]*)">/.exec(body)[1];
    for (const origin of everyone) {
      const mine = p.own.includes(origin);
      assert.equal(csp.includes(origin), mine, `${origin} in ${p.cookie}'s header`);
      assert.equal(meta.includes(origin), mine, `${origin} in ${p.cookie}'s page`);
    }
    if (p.own.length === 0) assert.equal(csp, DEFAULT_CSP);
    assert.equal(res.headers.get("Cache-Control"), "no-store");
    assert.equal(res.headers.get("Vary"), "Cookie");
  }
  // The static host's shared answer was never changed in place.
  assert.equal(shared.get("Content-Security-Policy"), DEFAULT_CSP);
  assert.equal(shared.get("Cache-Control"), null);
});

test("a conditional request never reaches the static host as one", async () => {
  const seen = [];
  const { next } = asset({ seen });
  await handle(request(`/approvals/${ID}`, "https://a.example.com", { "If-None-Match": '"abc"', "If-Modified-Since": "Fri, 13 Nov 2026 00:00:00 GMT" }), next);
  assert.equal(seen[0].headers.get("If-None-Match"), null);
  assert.equal(seen[0].headers.get("If-Modified-Since"), null);
});

test("the pin page allows only the address it checks, and only https", async () => {
  const { next } = asset();
  const res = await handle(request("/engines/add?address=https%3A%2F%2Fengine.example.com", "https://other.example.com"), next);
  assert.equal(res.headers.get("Content-Security-Policy"), policyWith(["https://engine.example.com"]));
  assert.equal(res.headers.get("Cache-Control"), "no-store");
  const plain = await handle(request("/engines/add", "https://other.example.com"), next);
  assert.equal(plain.headers.get("Content-Security-Policy"), DEFAULT_CSP);
  const bad = await handle(request("/engines/add?address=https%3A%2F%2Flocalhost", null), next);
  assert.equal(bad.headers.get("Content-Security-Policy"), DEFAULT_CSP);
});

test("other paths pass through untouched, and a missing page keeps the default", async () => {
  const { next } = asset();
  const passthrough = await handle(request("/lib/codec.js", "https://a.example.com"), next);
  assert.equal(passthrough.status, 404);
  assert.equal(passthrough.headers.get("Vary"), null);
  const missing = await handle(request(`/approvals/${ID}/extra`, "https://a.example.com"), next);
  assert.equal(missing.headers.get("Vary"), null, "not a page path");
});

test("the asset's own answer is never changed in place", async () => {
  for (const cookie of ["https://a.example.com", null]) {
    const cached = new Response(APPROVE_HTML, { status: 200, headers: { ...DEFAULT_HEADERS, "Content-Type": "text/html", Vary: "Accept-Encoding" } });
    const res = await handle(request(`/approvals/${ID}`, cookie), async () => cached);
    assert.notEqual(res, cached);
    assert.notEqual(res.headers, cached.headers);
    assert.equal(cached.headers.get("Content-Security-Policy"), DEFAULT_CSP);
    assert.equal(cached.headers.get("Cache-Control"), null);
    assert.equal(cached.headers.get("Vary"), "Accept-Encoding");
    assert.equal(res.headers.get("Vary"), "Accept-Encoding, Cookie", "Vary keeps what the asset varies on");
  }
});

test("the connect page gets its own policy, the same for everyone, never stored", async () => {
  assert.equal(CONNECT_SERVICE, PAGE_SERVICE);
  assert.equal(CONNECT_CSP, DEFAULT_CSP.replace(/connect-src [^;]*;/, `connect-src ${CONNECT_SERVICE};`));
  const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]*)">/.exec(CONNECT_HTML)[1];
  assert.match(meta, new RegExp(`; connect-src ${CONNECT_SERVICE.replace(/[.]/g, "\\.")};`));
  for (const path of ["/connect", "/connect/"]) {
    for (const cookie of [null, "https://a.example.com"]) {
      const cached = new Response(CONNECT_HTML, { status: 200, headers: { ...DEFAULT_HEADERS, "Content-Type": "text/html", ETag: '"abc"' } });
      const seen = [];
      const res = await handle(request(path, cookie, { "If-None-Match": '"abc"' }), async (req) => {
        seen.push(req);
        return cached;
      });
      assert.equal(res.status, 200);
      assert.equal(seen[0].headers.get("If-None-Match"), null, "never a 304");
      assert.equal(res.headers.get("Content-Security-Policy"), CONNECT_CSP, path);
      assert.equal(res.headers.get("Cache-Control"), "no-store");
      assert.equal(res.headers.get("ETag"), null);
      for (const [k, v] of Object.entries(DEFAULT_HEADERS)) if (k !== "Content-Security-Policy") assert.equal(res.headers.get(k), v);
      assert.doesNotMatch(res.headers.get("Content-Security-Policy"), /a\.example\.com/, "pins never reach the connect page");
      assert.equal(await res.text(), CONNECT_HTML, "the page itself is not changed");
      assert.equal(cached.headers.get("Content-Security-Policy"), DEFAULT_CSP, "the asset's answer is not changed in place");
    }
  }
  for (const path of ["/connect/x", "/connectx", "/connect/index.html"]) {
    const res = await handle(request(path, null), async () => new Response("x", { status: 200, headers: DEFAULT_HEADERS }));
    assert.equal(res.headers.get("Content-Security-Policy"), DEFAULT_CSP, path);
  }
});
