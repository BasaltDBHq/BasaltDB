// Engines this device pinned (CONTRACT.md, Direct transport, The pin page):
// the person types their engine's address on the portal, compares its
// fingerprint with the one their own computer printed, and confirms. Each
// pin is { address, engineKey, engineId, addedAt, lastUsedAt } in the
// portal origin's localStorage; nothing about a pin goes to the engine, the
// Vault or a link.
//
// The addresses alone also go in a first-party cookie, __Host-basalt-engines,
// which the portal's edge function reads to add exactly those origins to
// the page's connect-src (owner decision, 14 Nov 2026). The CSP is defence
// in depth: what makes a session safe is the pinned key checked in every
// handshake, and what makes a signature count is the person's passkey,
// checked in Postgres.

import { parseEngineAddress } from "./engineaddr.js";

export const PINS_KEY = "basalt-engines";
export const PINS_COOKIE = "__Host-basalt-engines";
// The cookie separates addresses with "|": a cookie value cannot hold a
// comma, a semicolon or a space, and no address can hold a "|".
export const COOKIE_SEPARATOR = "|";
export const MAX_PINS = 8;
// Browsers keep a cookie at most 400 days; every portal page writes it again.
const COOKIE_MAX_AGE = 400 * 24 * 60 * 60;

const ENGINE_KEY = /^[A-Za-z0-9_-]{122}$/;
const ENGINE_ID = /^[A-Za-z0-9_-]{22}$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function validPin(p) {
  return (
    p !== null &&
    typeof p === "object" &&
    parseEngineAddress(p.address) === p.address &&
    typeof p.engineKey === "string" &&
    ENGINE_KEY.test(p.engineKey) &&
    typeof p.engineId === "string" &&
    ENGINE_ID.test(p.engineId) &&
    typeof p.addedAt === "string" &&
    RFC3339.test(p.addedAt) &&
    (p.lastUsedAt === null || (typeof p.lastUsedAt === "string" && RFC3339.test(p.lastUsedAt)))
  );
}

// readPins returns the valid pins in storage (at most MAX_PINS, one per
// address); anything else in it is ignored, and an unreadable store reads
// as no pins.
export function readPins(storage) {
  let list;
  try {
    list = JSON.parse(storage.getItem(PINS_KEY) ?? "[]");
  } catch {
    return [];
  }
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const out = [];
  for (const p of list) {
    if (!validPin(p) || seen.has(p.address)) continue;
    seen.add(p.address);
    out.push({ address: p.address, engineKey: p.engineKey, engineId: p.engineId, addedAt: p.addedAt, lastUsedAt: p.lastUsedAt });
    if (out.length === MAX_PINS) break;
  }
  return out;
}

export function writePins(storage, pins) {
  storage.setItem(PINS_KEY, JSON.stringify(pins.slice(0, MAX_PINS)));
}

// byLastUse orders pins as the page tries them: the one that last opened a
// session first, then the most recently added.
export function byLastUse(pins) {
  const at = (p) => p.lastUsedAt ?? "";
  return [...pins].sort((a, b) => at(b).localeCompare(at(a)) || b.addedAt.localeCompare(a.addedAt));
}

export class PinError extends Error {
  constructor(message) {
    super(message);
    this.name = "PinError";
  }
}

// addPin returns pins with a new pin, refusing a full list and an address
// already pinned: a pinned address that now answers with another key is a
// warning to check, never something to replace in passing.
export function addPin(pins, { address, engineKey, engineId }, now = new Date()) {
  const existing = pins.find((p) => p.address === address);
  if (existing && existing.engineId === engineId) throw new PinError("This device already pinned this engine at this address.");
  if (existing) {
    throw new PinError(
      "This device pinned a different engine at this address. Check with basalt engine list --admin on your own computer; " +
        "if the engine there changed on purpose, remove the old pin on the engines page first.",
    );
  }
  if (pins.length >= MAX_PINS) throw new PinError(`This device already pinned ${MAX_PINS} engines. Remove one on the engines page first.`);
  const pin = { address, engineKey, engineId, addedAt: now.toISOString(), lastUsedAt: null };
  if (!validPin(pin)) throw new PinError("This engine's answer cannot be pinned.");
  return [...pins, pin];
}

export function removePin(pins, address) {
  return pins.filter((p) => p.address !== address);
}

// touchPin marks a pin as the one that last opened a session.
export function touchPin(pins, address, now = new Date()) {
  return pins.map((p) => (p.address === address ? { ...p, lastUsedAt: now.toISOString() } : p));
}

// cookieValue is the cookie's value for pins: their addresses, in the
// order the page tries them.
export function cookieValue(pins) {
  return byLastUse(pins)
    .map((p) => p.address)
    .join(COOKIE_SEPARATOR);
}

// pinsCookie is the document.cookie assignment that stores pins' addresses,
// or deletes the cookie when there are none. __Host- makes the browser
// refuse it unless it is Secure, Path=/ and without Domain, so no other
// basaltvault.app host can set it. SameSite=Lax, not Strict: a link the
// person clicks in a web chat is a cross-site navigation, and the edge
// function must see the cookie on it. The cookie carries no authority; it
// only lets the person's own page connect to their own engines.
export function pinsCookie(pins) {
  const value = cookieValue(pins);
  const age = value === "" ? 0 : COOKIE_MAX_AGE;
  return `${PINS_COOKIE}=${value}; Path=/; Secure; SameSite=Lax; Max-Age=${age}`;
}

// cookieIn is the cookie's value in a document.cookie string, or "".
export function cookieIn(cookies) {
  for (const part of String(cookies ?? "").split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === PINS_COOKIE) return rest.join("=");
  }
  return "";
}

// pinStore wraps the page's own storage and cookie. Every write updates
// both, so the next page load's CSP lists exactly this device's pins.
export function pinStore(storage = globalThis.localStorage, doc = globalThis.document) {
  const save = (pins) => {
    writePins(storage, pins);
    doc.cookie = pinsCookie(pins);
    return pins;
  };
  return {
    list: () => readPins(storage),
    add: (fields) => save(addPin(readPins(storage), fields)),
    remove: (address) => save(removePin(readPins(storage), address)),
    touch: (address) => save(touchPin(readPins(storage), address)),
    // inCookie reports whether the cookie already lists exactly this
    // device's pins, as the edge function read it for this page load.
    inCookie: () => cookieIn(doc.cookie) === cookieValue(readPins(storage)),
    syncCookie: () => {
      doc.cookie = pinsCookie(readPins(storage));
    },
  };
}
