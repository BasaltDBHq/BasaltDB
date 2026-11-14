// Runs with `node --test web/lib/*.test.mjs` (make web-check). A hash link
// shows the request box; the file or the pasted blocks, checked against h,
// are loaded as a long link's fragment (CONTRACT.md, The request file and
// pasted blocks).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { loadOrPaste } from "./page.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../api/mcp/links/request-file.json", import.meta.url), "utf8"),
);
const three = vectors.vectors.find((v) => v.blocks && v.blocks.length === 3);
const other = vectors.vectors.find((v) => v !== three && v.blocks);

function fakeDocument() {
  const nodes = {};
  const ids = ["error", "error-text", "main", "paste-box", "paste", "paste-read", "paste-status",
    "request-box", "request-file", "request-paste", "request-read", "request-status"];
  for (const id of ids) {
    nodes[id] = { hidden: true, textContent: "", value: "", disabled: false, files: [], listeners: {} };
    nodes[id].addEventListener = (type, fn) => {
      nodes[id].listeners[type] = fn;
    };
  }
  globalThis.document = { getElementById: (id) => nodes[id] };
  return nodes;
}

function start(v) {
  const nodes = fakeDocument();
  globalThis.window = { location: { hash: `#h=${v.h}`, pathname: "/reverts/x" } };
  const seen = [];
  const load = async (hash) => {
    seen.push(hash);
    return "request";
  };
  const result = loadOrPaste(load, (err) => `failed: ${err.message}`);
  return { nodes, seen, result };
}

async function paste(nodes, text) {
  nodes["request-paste"].value = text;
  await nodes["request-read"].listeners.click();
}

test("a hash link shows the request box and loads nothing yet", () => {
  const { nodes, seen } = start(three);
  assert.equal(nodes["request-box"].hidden, false);
  assert.deepEqual(seen, []);
});

test("shuffled blocks over several pastes rebuild the exact request", async () => {
  const { nodes, seen, result } = start(three);
  await paste(nodes, three.blocks[2]);
  assert.match(nodes["request-status"].textContent, /1 of 3 blocks; still missing: 1, 2\./);
  await paste(nodes, other.blocks[0]);
  assert.match(nodes["request-status"].textContent, /another request/);
  await paste(nodes, `${three.blocks[0]}\n\nBasaltBot\n${three.blocks[1]}`);
  assert.equal(await result, "request");
  assert.deepEqual(seen, [`#${three.text}`]);
  assert.equal(nodes["request-box"].hidden, true);
});

test("the file the agent sent loads the request; a wrong file fails the h check", async () => {
  const { nodes, seen, result } = start(three);
  const pick = async (content) => {
    nodes["request-file"].files = [{ size: content.length, text: async () => content }];
    await nodes["request-file"].listeners.change();
  };
  await pick(other.text);
  assert.match(nodes["request-status"].textContent, /does not match the link/);
  assert.deepEqual(seen, []);
  await pick(`${three.text}\n`);
  assert.equal(await result, "request");
  assert.deepEqual(seen, [`#${three.text}`]);
});

test("a file over 4 MiB is refused before it is read", async () => {
  const { nodes, seen } = start(three);
  let read = false;
  nodes["request-file"].files = [{ size: 4 * 1024 * 1024 + 1, text: async () => { read = true; return ""; } }];
  await nodes["request-file"].listeners.change();
  assert.equal(read, false);
  assert.match(nodes["request-status"].textContent, /too big/);
  assert.deepEqual(seen, []);
});
