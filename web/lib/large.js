// A value over 1 MiB of text is not drawn on the signing pages: they show
// its size and sha256, the same two numbers the agent's marker carries
// (CONTRACT.md, Large values). The page keeps the value and signs it whole.
import { displayValue } from "./codec.js";

// LARGE_LIMIT is the most text (UTF-8 bytes) a page draws. It tests the
// text, not the result budget's cost, on purpose.
export const LARGE_LIMIT = 1 << 20;

const KIB = 1 << 10;
const encoder = new TextEncoder();
// hashes keeps the last few digests, so a page does not hold every large
// text it has shown. A Map iterates in insertion order.
const HASHES_KEPT = 16;
const hashes = new Map();

// valueTextOf is a value's text as the marker measures it: a string's
// characters (the line's slice with its escapes decoded), anything else the
// raw slice the line carries.
export function valueTextOf(value, raw) {
  return displayValue(value, raw);
}

// sizeText is a size in KiB or MiB with one decimal.
export function sizeText(bytes) {
  return bytes < LARGE_LIMIT ? `${(bytes / KIB).toFixed(1)} KiB` : `${(bytes / LARGE_LIMIT).toFixed(1)} MiB`;
}

// largeInfo is null for text a page draws, else {bytes}. A UTF-16 unit takes
// at least one and at most three bytes, so text of a third of the limit or
// less is never large.
export function largeInfo(text) {
  if (text.length * 3 <= LARGE_LIMIT) return null;
  const bytes = encoder.encode(text).length;
  return bytes > LARGE_LIMIT ? { bytes } : null;
}

function hex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

// largeHash is the lowercase hex SHA-256 of the text in UTF-8.
export async function largeHash(text) {
  let h = hashes.get(text);
  if (h === undefined) {
    h = hex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
    hashes.set(text, h);
    if (hashes.size > HASHES_KEPT) hashes.delete(hashes.keys().next().value);
  }
  return h;
}

largeHash.cached = (text) => hashes.get(text);

// tooLargeText is what the page shows in place of a large value.
export function tooLargeText(bytes, hash) {
  return `too large to show: ${sizeText(bytes)}, sha256 ${hash}\nYour signature covers the full value.`;
}
