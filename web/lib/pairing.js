// The pairing code (CONTRACT.md, CLI): the short code the registration page
// shows after it hands the passkey back to basalt init, which the person
// types into init so init keeps their registration and no other. Go's
// internal/passkey.PairingCode computes the same code; both run
// api/mcp/passkey/pairing-code.json.
import { sha256, utf8 } from "./codec.js";

const DOMAIN = "basalt-pairing.1\n";
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const LENGTH = 8;

// crockford32 encodes 5 bytes as 8 characters, most significant bits first.
function crockford32(bytes) {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  let out = "";
  for (let i = LENGTH - 1; i >= 0; i--) out += ALPHABET[Number((value >> BigInt(5 * i)) & 31n)];
  return out;
}

// pairingCode is "XXXX-XXXX": Crockford base32 of the first 5 bytes of
// sha256("basalt-pairing.1\n" || challenge || credentialId || x || y).
export async function pairingCode(challenge, credentialId, x, y) {
  const parts = [utf8(DOMAIN), challenge, credentialId, x, y];
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  const s = crockford32((await sha256(all)).slice(0, 5));
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

// pairingCoordinates is the P-256 point's x and y: the last 64 bytes of the
// SPKI public key (an uncompressed point) the browser exports.
export function pairingCoordinates(spki) {
  if (spki.length < 65 || spki[spki.length - 65] !== 0x04) throw new Error("the passkey's public key is not an uncompressed P-256 point");
  return { x: spki.slice(spki.length - 64, spki.length - 32), y: spki.slice(spki.length - 32) };
}

// normalizePairingCode reads a code as a person types it: trimmed, any case,
// with or without the dash or spaces, O for 0 and I or L for 1. It returns
// the canonical 8 characters, or null when it is not 8 Crockford characters.
export function normalizePairingCode(s) {
  const t = String(s ?? "")
    .trim()
    .toUpperCase()
    .replace(/[- ]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  if (t.length !== LENGTH) return null;
  for (const ch of t) if (!ALPHABET.includes(ch)) return null;
  return t;
}
