// Runs with `node --test web/lib/*.test.mjs` (make web-check). A pressed
// button says it is working: busy() in page.js, and the approve, revert and
// registration pages that use it. The setup, connect, remove and plugin pages
// are covered in their own test files.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";

import { parseApprovalRequest, parseRevertRequest } from "./codec.js";
import { busy } from "./page.js";
import { summarize } from "./summary.js";
// Imported before any document exists, so the pages do not start themselves.
import { approve } from "./approve.js";
import { blocked, includeOthers, reject, showValues, sign } from "./revert.js";
import { register } from "./register.js";

// A lazy page: every element asked for exists, with the little of the DOM the
// pages use.
function fakePage() {
  const nodes = new Map();
  const make = (id) => {
    const n = {
      id,
      hidden: false,
      disabled: false,
      checked: false,
      value: "",
      textContent: "",
      className: "",
      children: [],
      attrs: {},
      style: {},
      listeners: {},
    };
    n.setAttribute = (k, v) => { n.attrs[k] = String(v); };
    n.getAttribute = (k) => n.attrs[k] ?? null;
    n.addEventListener = (t, f) => { n.listeners[t] = f; };
    n.replaceChildren = (...c) => { n.children = c; };
    n.append = (...c) => { n.children.push(...c); };
    n.appendChild = (c) => { n.children.push(c); return c; };
    n.classList = { toggle() {}, add() {}, remove() {} };
    n.focus = () => {};
    n.select = () => {};
    return n;
  };
  globalThis.document = {
    getElementById: (id) => {
      if (!nodes.has(id)) nodes.set(id, make(id));
      return nodes.get(id);
    },
    createElement: (tag) => Object.assign(make(""), { tag }),
  };
  return (id) => globalThis.document.getElementById(id);
}

const cancelled = () => Object.assign(new Error("x"), { name: "NotAllowedError" });

// prompt is a passkey prompt the test answers by hand.
function prompting() {
  const out = { asked: 0 };
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    writable: true,
    value: {
      credentials: {
        get: () => {
          out.asked++;
          return new Promise((resolve, reject) => { out.answer = { resolve, reject }; });
        },
        create: () => {
          out.asked++;
          return new Promise((resolve, reject) => { out.answer = { resolve, reject }; });
        },
      },
    },
  });
  return out;
}

// answered is a passkey answer as the browser gives it.
const answered = () => ({
  rawId: new Uint8Array([1, 2, 3]).buffer,
  response: {
    authenticatorData: new Uint8Array([4]).buffer,
    clientDataJSON: new Uint8Array([123, 125]).buffer,
    signature: new Uint8Array([5, 6]).buffer,
  },
});

// session is an engine that answers every request with status.
const session = (status = 409, body = { code: "APPROVAL_INVALID", message: "this was already used" }) => ({
  closed: false,
  calls: [],
  async request(...args) {
    this.calls.push(args);
    return { status, body: JSON.stringify(body) };
  },
  close() {
    this.closed = true;
  },
});

const fixture = (name) => JSON.parse(readFileSync(new URL(`../../internal/core/${name}/testdata/fixtures.json`, import.meta.url), "utf8")).request;
const later = (req) => {
  req.binding = { ...req.binding, expiresAt: new Date(Date.now() + 600000) };
  return req;
};

const isBusy = (n) => n.getAttribute("aria-busy") === "true";

test("busy marks the button at once, refuses a second press, and done gives the button back as it was", () => {
  const $ = fakePage();
  const b = $("go");
  b.textContent = "Check it";
  const done = busy(b, "Checking…");
  assert.ok(isBusy(b));
  assert.equal(b.textContent, "Checking…");
  assert.equal(b.disabled, true);
  assert.equal(busy(b, "Checking…"), null, "a second press gets nothing");
  done.label("Setting up…");
  assert.equal(b.textContent, "Setting up…");
  done();
  assert.ok(!isBusy(b));
  assert.equal(b.textContent, "Check it");
  assert.equal(b.disabled, false);
  done.label("late");
  assert.equal(b.textContent, "Check it", "a finished button is not relabeled");
  assert.ok(busy(b, "Again…"), "pressable again once done");
});

test("busy leaves a label the page painted meanwhile, and gives an icon back", () => {
  const $ = fakePage();
  const b = $("go");
  b.textContent = "Yes";
  const done = busy(b, "Checking…");
  b.textContent = "Not this one";
  done();
  assert.equal(b.textContent, "Not this one");

  const icon = { tag: "svg", textContent: "" };
  const withIcon = $("icon");
  withIcon.childNodes = [icon, { textContent: "Show values" }];
  withIcon.textContent = "Show values";
  const again = busy(withIcon, "Waiting for your passkey…");
  again();
  assert.deepEqual(withIcon.children, [icon, { textContent: "Show values" }]);
});

test("registration: Create passkey waits for the passkey, a second press opens no second prompt, a cancelled prompt puts the button back", async () => {
  const $ = fakePage();
  const p = prompting();
  const rp = { rpId: "basaltvault.app" };
  const req = { challenge: new Uint8Array(32), userId: new Uint8Array(16), userName: "u", displayName: "d" };
  $("register").textContent = "Register a passkey";
  const first = register(rp, req);
  assert.ok(isBusy($("register")));
  assert.equal($("register").textContent, "Waiting for your passkey…");
  assert.equal($("register").disabled, true);
  await register(rp, req);
  assert.equal(p.asked, 1);
  p.answer.reject(cancelled());
  await first;
  assert.ok(!isBusy($("register")));
  assert.equal($("register").textContent, "Register a passkey");
  assert.equal($("register").disabled, false);
  assert.match($("status").textContent, /cancelled or timed out/);
});

test("approval: Sign waits for the passkey, then says Sending…, a cancelled prompt and a refused relay put the label back", async () => {
  const $ = fakePage();
  const p = prompting();
  const req = later(await parseApprovalRequest("#" + fixture("approval").fragment));
  const summary = summarize(req.lines);
  const s = session();
  const relay = { path: "/approvals/x/response", secret: "s", session: s };
  $("cascade-ok").checked = true;
  $("approve").textContent = "Sign with your passkey";
  const first = approve({ rpId: "localhost" }, req, summary, relay);
  assert.ok(isBusy($("approve")));
  assert.equal($("approve").textContent, "Waiting for your passkey…");
  await approve({ rpId: "localhost" }, req, summary, relay);
  assert.equal(p.asked, 1, "a second press opens no second prompt");
  p.answer.reject(cancelled());
  await first;
  assert.ok(!isBusy($("approve")));
  assert.equal($("approve").textContent, "Sign with your passkey");
  assert.equal($("approve").disabled, false, "not stuck busy");
  assert.match($("status").textContent, /cancelled or timed out/);

  const second = approve({ rpId: "localhost" }, req, summary, relay);
  p.answer.resolve(answered());
  await second;
  assert.equal(s.calls.length, 1, "the signature went to the engine once");
  assert.ok(!isBusy($("approve")));
  assert.equal($("approve").textContent, "Sign with your passkey");
  assert.equal($("approve").disabled, true, "the engine refused: the page says so and the button stays off");
  assert.equal($("done").hidden, false);
});

test("revert: Sign, Reject, Include others and Show values show their working labels and come back", async () => {
  const $ = fakePage();
  const p = prompting();
  const req = later(await parseRevertRequest("#" + fixture("revert").fragment));
  const s = session(409, { code: "REVERT_INVALID", message: "this was already used" });
  const relay = { id: req.revertId, secret: "s", session: s };
  const state = { rp: { rpId: "localhost" }, req, relay, catalog: null, known: [], choices: null, busy: false, expired: false, shown: new Map(), revealDone: false, valuesHidden: false };

  $("sign").textContent = "Sign with your passkey";
  const signing = sign(state.rp, state);
  assert.ok(isBusy($("sign")));
  assert.equal($("sign").textContent, "Waiting for your passkey…");
  await sign(state.rp, state);
  assert.equal(p.asked, 1, "a second press opens no second prompt");
  p.answer.reject(cancelled());
  await signing;
  assert.ok(!isBusy($("sign")));
  assert.equal($("sign").textContent, "Sign with your passkey");
  assert.equal($("sign").disabled, blocked(req) !== null);
  assert.match($("status").textContent, /cancelled or timed out/);

  $("note").value = "no";
  $("reject-send").textContent = "Send reject";
  const rejecting = reject(state);
  assert.ok(isBusy($("reject-send")));
  assert.equal($("reject-send").textContent, "Sending…");
  assert.equal($("reject-cancel").disabled, true);
  await reject(state);
  assert.equal(s.calls.length, 1, "a second press sends nothing");
  await rejecting;
  assert.ok(!isBusy($("reject-send")));
  assert.equal($("reject-send").textContent, "Send reject");
  assert.equal($("reject-send").disabled, false);
  assert.equal($("reject-cancel").disabled, false);
  assert.match($("reject-status").textContent, /this was already used/);

  $("widen").textContent = "Include other agents' changes";
  const widening = includeOthers(state);
  assert.ok(isBusy($("widen")));
  assert.equal($("widen").textContent, "Waiting for your passkey…");
  assert.equal(includeOthers(state), undefined, "a second press does nothing");
  await widening.catch(() => {});
  assert.ok(!isBusy($("widen")));

  $("reveal").textContent = "Show values with passkey";
  const revealing = showValues(state);
  assert.ok(isBusy($("reveal")));
  assert.equal($("reveal").textContent, "Waiting for your passkey…");
  await revealing;
  assert.ok(!isBusy($("reveal")));
  assert.equal($("reveal").textContent, "Show values with passkey");
});

test("no button that starts a call is left on a bare disabled = true", () => {
  // Every `.disabled = true` in the pages' scripts, by file. A button that
  // starts a network call, a job or a passkey prompt goes through busy(); the
  // sites below only keep a button off after the page said how it went, while
  // a field is empty or a note refused, lock the Cancel that sits beside a
  // busy button, or switch off a choice that is not offered.
  const allowed = {
    "approve.js": 4,
    "page.js": 3,
    "pickviews.js": 1,
    "plugin.js": 1,
    "revert.js": 3,
    "setup.js": 2,
  };
  const found = {};
  for (const f of readdirSync(new URL(".", import.meta.url)).filter((n) => n.endsWith(".js"))) {
    const n = readFileSync(new URL(`./${f}`, import.meta.url), "utf8").split("\n").filter((l) => /\.disabled = true;/.test(l) && !/^\s*\/\//.test(l)).length;
    if (n > 0) found[f] = n;
  }
  assert.deepEqual(found, allowed);
});
