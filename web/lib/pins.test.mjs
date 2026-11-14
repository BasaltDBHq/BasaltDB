// Pins on this device and the cookie the portal's edge function reads.
import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_PINS, PINS_COOKIE, PinError, addPin, byLastUse, cookieIn, pinStore, pinsCookie, readPins, removePin } from "./pins.js";

const KEY = "A".repeat(122);
const ID = "a".repeat(22);
const NOW = new Date("2026-11-14T10:00:00Z");

function memory(init = {}) {
  const m = new Map(Object.entries(init));
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), m };
}

const fields = (address, engineId = ID) => ({ address, engineKey: KEY, engineId });

test("a pin is added once per address, at most 8", () => {
  let pins = addPin([], fields("https://engine.example.com"), NOW);
  assert.deepEqual(pins, [{ address: "https://engine.example.com", engineKey: KEY, engineId: ID, addedAt: "2026-11-14T10:00:00.000Z", lastUsedAt: null }]);
  assert.throws(() => addPin(pins, fields("https://engine.example.com"), NOW), /already pinned this engine/);
  assert.throws(() => addPin(pins, fields("https://engine.example.com", "b".repeat(22)), NOW), PinError);
  for (let i = 1; i < MAX_PINS; i++) pins = addPin(pins, fields(`https://e${i}.example.com`), NOW);
  assert.throws(() => addPin(pins, fields("https://e9.example.com"), NOW), /already pinned 8 engines/);
});

test("a pin whose fields break the rules is refused", () => {
  assert.throws(() => addPin([], fields("https://localhost"), NOW), PinError);
  assert.throws(() => addPin([], { address: "https://engine.example.com", engineKey: "short", engineId: ID }, NOW), PinError);
});

test("readPins keeps only valid, distinct pins and survives junk", () => {
  const good = { address: "https://engine.example.com", engineKey: KEY, engineId: ID, addedAt: "2026-11-14T10:00:00.000Z", lastUsedAt: null };
  const store = memory({
    "basalt-engines": JSON.stringify([good, good, { ...good, address: "https://evil.example.com; script-src *" }, { ...good, address: "https://x.example.com", extra: 1 }, null, 7]),
  });
  const pins = readPins(store);
  assert.equal(pins.length, 2);
  assert.deepEqual(Object.keys(pins[1]).sort(), ["addedAt", "address", "engineId", "engineKey", "lastUsedAt"]);
  assert.deepEqual(readPins(memory({ "basalt-engines": "{" })), []);
  assert.deepEqual(readPins(memory({ "basalt-engines": '{"a":1}' })), []);
});

test("byLastUse puts the pin that last opened a session first", () => {
  const a = { address: "https://a.example.com", addedAt: "2026-11-01T00:00:00Z", lastUsedAt: null };
  const b = { address: "https://b.example.com", addedAt: "2026-11-02T00:00:00Z", lastUsedAt: "2026-11-10T00:00:00Z" };
  const c = { address: "https://c.example.com", addedAt: "2026-11-03T00:00:00Z", lastUsedAt: null };
  assert.deepEqual(byLastUse([a, b, c]).map((p) => p.address), ["https://b.example.com", "https://c.example.com", "https://a.example.com"]);
});

test("the cookie is __Host-, Secure, Path=/, SameSite=Lax, with no Domain", () => {
  const pins = addPin(addPin([], fields("https://a.example.com"), NOW), fields("https://b.example.com:8443"), NOW);
  const c = pinsCookie(pins);
  assert.match(c, /^__Host-basalt-engines=https:\/\/a\.example\.com\|https:\/\/b\.example\.com:8443; /);
  assert.match(c, /; Path=\/; Secure; SameSite=Lax; Max-Age=34560000$/);
  assert.doesNotMatch(c, /Domain/i);
  assert.match(pinsCookie([]), /^__Host-basalt-engines=; Path=\/; Secure; SameSite=Lax; Max-Age=0$/);
});

test("cookieIn reads only the pins cookie", () => {
  assert.equal(cookieIn(`a=1; ${PINS_COOKIE}=https://a.example.com|https://b.example.com; b=2`), "https://a.example.com|https://b.example.com");
  assert.equal(cookieIn("x__Host-basalt-engines=nope"), "");
  assert.equal(cookieIn(""), "");
});

test("the store writes storage and cookie together", () => {
  const storage = memory();
  const doc = { cookie: "" };
  const store = pinStore(storage, doc);
  store.add(fields("https://a.example.com"));
  assert.equal(store.list().length, 1);
  assert.match(doc.cookie, /^__Host-basalt-engines=https:\/\/a\.example\.com;/);
  // A browser keeps only name=value in document.cookie.
  doc.cookie = doc.cookie.split(";")[0];
  assert.equal(store.inCookie(), true);
  store.remove("https://a.example.com");
  assert.deepEqual(removePin(store.list(), "x"), []);
  assert.match(doc.cookie, /Max-Age=0$/);
});
