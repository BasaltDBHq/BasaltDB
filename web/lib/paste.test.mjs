// Runs with `node --test web/lib/*.test.mjs` (make web-check). The paste box
// hands the loader only a fragment, whatever origin or path the text holds.
import { test } from "node:test";
import assert from "node:assert/strict";

import { RelayError } from "./local.js";
import { MAX_PASTE_CHARS, loadOrPaste } from "./page.js";

function fakeDocument() {
  const nodes = {};
  for (const id of ["error", "error-text", "main", "paste-box", "paste", "paste-read", "paste-status"]) {
    nodes[id] = { hidden: false, textContent: "", value: "", disabled: false, listeners: {} };
    nodes[id].addEventListener = (type, fn) => {
      nodes[id].listeners[type] = fn;
    };
  }
  globalThis.document = { getElementById: (id) => nodes[id] };
  return nodes;
}

test("a failing fragment shows the paste box, and the pasted fragment is loaded", async () => {
  const nodes = fakeDocument();
  globalThis.window = { location: { hash: "#2.AbC.bad", pathname: "/approvals/own-id" } };
  const seen = [];
  const load = async (hash) => {
    seen.push(hash);
    if (hash !== "#1.Good") throw new Error("does not decode");
    return "request";
  };
  const result = loadOrPaste(load, (err) => `failed: ${err.message}`);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(seen, ["#2.AbC"]);
  assert.equal(nodes["paste-box"].hidden, false);
  assert.equal(nodes["error-text"].textContent, "failed: does not decode");

  nodes.paste.value = "Open https://evil.example/approvals/other#1.Good\n\nThanks";
  await nodes["paste-read"].listeners.click();
  assert.equal(await result, "request");
  assert.deepEqual(seen, ["#2.AbC", "#1.Good"]);
  assert.equal(nodes["paste-box"].hidden, true);
  assert.equal(nodes.error.hidden, true);
});

test("a paste over the cap is refused before it is read", async () => {
  const nodes = fakeDocument();
  globalThis.window = { location: { hash: "" } };
  const seen = [];
  loadOrPaste(
    async (hash) => {
      seen.push(hash);
      throw new Error("missing");
    },
    (err) => err.message,
  );
  await new Promise((resolve) => setImmediate(resolve));
  nodes.paste.value = `#1.Good${"a".repeat(MAX_PASTE_CHARS)}`;
  await nodes["paste-read"].listeners.click();
  assert.match(nodes["paste-status"].textContent, /too long/);
  assert.deepEqual(seen, ["#"]);
});

test("an answer of the engine other than NOT_FOUND does not show the paste box", async () => {
  const nodes = fakeDocument();
  nodes["paste-box"].hidden = true;
  globalThis.window = { location: { hash: "#s=q3Jv8sLk2mT0xYp1aBcD9w" } };
  for (const code of ["UNAVAILABLE", "EXPIRED", "ALREADY_USED", ""]) {
    const err = new RelayError("no", code);
    await assert.rejects(loadOrPaste(async () => { throw err; }, (e) => e.message), err);
    assert.equal(nodes["paste-box"].hidden, true);
  }
});

test("NOT_FOUND shows the paste box", async () => {
  const nodes = fakeDocument();
  nodes["paste-box"].hidden = true;
  globalThis.window = { location: { hash: "#s=q3Jv8sLk2mT0xYp1aBcD9w" } };
  loadOrPaste(async () => { throw new RelayError("gone", "NOT_FOUND"); }, (e) => e.message);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(nodes["paste-box"].hidden, false);
});

test("a paste without a link says so and loads nothing", async () => {
  const nodes = fakeDocument();
  globalThis.window = { location: { hash: "" } };
  const seen = [];
  loadOrPaste(
    async (hash) => {
      seen.push(hash);
      throw new Error("missing");
    },
    (err) => err.message,
  );
  await new Promise((resolve) => setImmediate(resolve));
  nodes.paste.value = "Thanks, I approved it.";
  await nodes["paste-read"].listeners.click();
  assert.match(nodes["paste-status"].textContent, /No link found/);
  assert.deepEqual(seen, ["#"]);
});
