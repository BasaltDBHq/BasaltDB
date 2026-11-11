// Format 2, the compact request (CONTRACT.md, Approvals, Format 2): the
// texts of a request (the binding text, then its lines) carried as shapes
// and values, rebuilt here to the exact text Postgres printed. Pure
// functions, mirrored by Go's internal/linkcodec; both run the shared
// vectors in api/mcp/links/compact-request.json.
//
// A link is untrusted: every count and length is capped, and a wrong
// rebuild fails closed, since the lines then no longer hash to the
// binding's rowsHash.

export class CompactError extends Error {
  constructor(message) {
    super(message);
    this.name = "CompactError";
  }
}

export const MAX_TEXTS_BYTES = 1 << 20; // the rebuilt texts, in UTF-8 bytes
const MAX_ENTRIES = 64; // a revert line has 10 top-level keys
const MAX_COLUMNS = 1600; // Postgres's MaxHeapAttributeNumber
const MAX_DEPTH = 32; // arrays nested inside one value

const encoder = new TextEncoder();

function fail(message) {
  throw new CompactError(message);
}

function isString(v) {
  return typeof v === "string";
}

// safeInteger accepts what Go's linkcodec accepts: an integer of magnitude at
// most 2^53 - 1 that is not -0.
function safeInteger(v) {
  return typeof v === "number" && Number.isSafeInteger(v) && !Object.is(v, -0);
}

// quote writes s as Postgres's escape_json does.
const ESCAPES = { '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };

export function quote(s) {
  let out = '"';
  for (const ch of s) {
    const esc = ESCAPES[ch];
    if (esc !== undefined) out += esc;
    else if (ch < " ") out += "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

function emit(value, depth) {
  if (isString(value)) return quote(value);
  if (value === true || value === false || value === null) return String(value);
  if (typeof value === "number") {
    if (!safeInteger(value)) fail(`value ${value} is not a safe integer`);
    return String(value);
  }
  if (Array.isArray(value)) {
    if (depth >= MAX_DEPTH) fail(`value nests arrays deeper than ${MAX_DEPTH}`);
    return "[" + value.map((v) => emit(v, depth + 1)).join(", ") + "]";
  }
  const keys = Object.keys(value);
  if (keys.length !== 1 || keys[0] !== "raw" || !isString(value.raw)) fail('an object value must be {"raw": text}');
  return value.raw;
}

// checkShape returns the shape's slot count, or throws.
function checkShape(shape, i) {
  if (!Array.isArray(shape) || shape.length === 0 || shape.length > MAX_ENTRIES) {
    fail(`shape ${i} must have 1 to ${MAX_ENTRIES} entries`);
  }
  let slots = 0;
  for (const e of shape) {
    if (isString(e)) {
      slots++;
      continue;
    }
    const ok = Array.isArray(e) && e.length === 2 && isString(e[0]) && Array.isArray(e[1]) && e[1].every(isString);
    if (!ok) fail(`shape ${i}: an entry is "name" or ["name", ["column", ...]]`);
    if (e[1].length > MAX_COLUMNS) fail(`shape ${i}: entry has more than ${MAX_COLUMNS} columns`);
    slots += e[1].length;
  }
  return slots;
}

// build writes one shaped text; it stops once the text passes budget
// characters, which are never more than its UTF-8 bytes.
function build(shape, values, budget) {
  let next = 0;
  const parts = [];
  let length = 0;
  for (const e of shape) {
    let part;
    if (isString(e)) {
      part = quote(e) + ": " + emit(values[next++], 0);
    } else {
      const cols = e[1].map((col) => quote(col) + ": " + emit(values[next++], 0));
      part = quote(e[0]) + ": {" + cols.join(", ") + "}";
    }
    length += part.length;
    if (length > budget) fail(`texts rebuild past ${MAX_TEXTS_BYTES >> 20} MiB`);
    parts.push(part);
  }
  return "{" + parts.join(", ") + "}";
}

// rebuildTexts rebuilds [shapes, texts]: at least one and at most maxTexts
// texts, every shape used, each shaped text with exactly its shape's slots,
// and at most MAX_TEXTS_BYTES in all.
export function rebuildTexts(payload, maxTexts) {
  if (!Array.isArray(payload) || payload.length !== 2 || !Array.isArray(payload[0]) || !Array.isArray(payload[1])) {
    fail("is not [shapes, lines]");
  }
  const [shapes, texts] = payload;
  if (texts.length === 0) fail("has no lines");
  if (texts.length > maxTexts) fail(`has ${texts.length} lines, at most ${maxTexts}`);
  if (shapes.length > texts.length) fail(`has ${shapes.length} shapes for ${texts.length} lines`);
  const slots = shapes.map(checkShape);
  const used = new Array(shapes.length).fill(false);
  const out = [];
  let total = 0;
  for (const t of texts) {
    let text;
    if (isString(t)) {
      text = t;
    } else {
      if (!Array.isArray(t) || t.length === 0 || !safeInteger(t[0])) fail('a line is "text" or [shape, value, ...]');
      const i = t[0];
      if (i < 0 || i >= shapes.length) fail(`a line names shape ${i} of ${shapes.length}`);
      used[i] = true;
      if (t.length - 1 !== slots[i]) fail(`a line has ${t.length - 1} values, its shape ${slots[i]}`);
      text = build(shapes[i], t.slice(1), MAX_TEXTS_BYTES - total);
    }
    total += encoder.encode(text).length;
    if (total > MAX_TEXTS_BYTES) fail(`texts rebuild past ${MAX_TEXTS_BYTES >> 20} MiB`);
    out.push(text);
  }
  const unused = used.indexOf(false);
  if (unused !== -1) fail(`shape ${unused} is unused`);
  return out;
}
