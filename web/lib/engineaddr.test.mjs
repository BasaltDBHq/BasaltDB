// The portal checks engine addresses with the grammar laptop init and
// Postgres use: the same cases as internal/engineaddr's Go test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseEngineAddress, socketOrigin } from "./engineaddr.js";

const vectors = JSON.parse(readFileSync(new URL("../../internal/engineaddr/testdata/addresses.json", import.meta.url), "utf8"));

test("every address the Go grammar accepts, with its written form", () => {
  assert.ok(Object.keys(vectors.accept).length > 0);
  for (const [input, want] of Object.entries(vectors.accept)) {
    assert.equal(parseEngineAddress(input), want, input);
  }
});

test("every address the Go grammar refuses", () => {
  assert.ok(vectors.refuse.length > 0);
  for (const input of vectors.refuse) {
    assert.equal(parseEngineAddress(input), null, JSON.stringify(input));
  }
});

test("anything but a string is refused", () => {
  for (const v of [undefined, null, 1, ["https://engine.example.com"], { toString: () => "https://engine.example.com" }]) {
    assert.equal(parseEngineAddress(v), null);
  }
});

test("the socket origin keeps host and port", () => {
  assert.equal(socketOrigin("https://engine.example.com"), "wss://engine.example.com");
  assert.equal(socketOrigin("https://engine.example.com:8443"), "wss://engine.example.com:8443");
});
