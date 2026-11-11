// deflateEnd walks a deflate-raw stream (RFC 1951) without inflating it and
// returns the number of bytes up to the end of its final block, so a page can
// refuse bytes after the stream itself instead of relying on the browser's
// DecompressionStream to throw. Only the block structure is checked;
// DecompressionStream still inflates and checks the rest. Pure, so it runs
// under `node --test`. Every symbol uses at least one bit, so the walk is
// bounded by the input's length.

export class DeflateError extends Error {
  constructor(message) {
    super(message);
    this.name = "DeflateError";
  }
}

const MAX_BITS = 15;
const MAX_LIT_CODES = 286;
const MAX_DIST_CODES = 30;
const FIXED_LIT_CODES = 288;
const LENGTH_EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_EXTRA = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
const END_OF_BLOCK = 256;

function fail(message) {
  throw new DeflateError(message);
}

class Bits {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
    this.buf = 0;
    this.cnt = 0;
  }

  // need reads need bits (at most 16), least significant first.
  need(n) {
    while (this.cnt < n) {
      if (this.pos >= this.bytes.length) fail("the deflate stream is cut short");
      this.buf |= this.bytes[this.pos++] << this.cnt;
      this.cnt += 8;
    }
    const v = this.buf & ((1 << n) - 1);
    this.buf >>>= n;
    this.cnt -= n;
    return v;
  }

  // align drops the bits left in the current byte.
  align() {
    this.buf = 0;
    this.cnt = 0;
  }
}

// huffman builds a canonical code table from code lengths (as zlib's puff).
function huffman(lengths) {
  const count = new Array(MAX_BITS + 1).fill(0);
  for (const len of lengths) count[len]++;
  let left = 1;
  for (let len = 1; len <= MAX_BITS; len++) {
    left = (left << 1) - count[len];
    if (left < 0) fail("an over-subscribed Huffman code");
  }
  const offs = new Array(MAX_BITS + 2).fill(0);
  for (let len = 1; len <= MAX_BITS; len++) offs[len + 1] = offs[len] + count[len];
  const symbol = [];
  lengths.forEach((len, sym) => {
    if (len !== 0) symbol[offs[len]++] = sym;
  });
  return { count, symbol };
}

function decode(bits, h) {
  let code = 0;
  let first = 0;
  let index = 0;
  for (let len = 1; len <= MAX_BITS; len++) {
    code |= bits.need(1);
    const count = h.count[len];
    if (code - count < first) return h.symbol[index + (code - first)];
    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }
  return fail("an invalid Huffman code");
}

function fixedTables() {
  const lit = new Array(FIXED_LIT_CODES);
  lit.fill(8, 0, 144);
  lit.fill(9, 144, 256);
  lit.fill(7, 256, 280);
  lit.fill(8, 280, FIXED_LIT_CODES);
  return { lit: huffman(lit), dist: huffman(new Array(MAX_DIST_CODES).fill(5)) };
}

function dynamicTables(bits) {
  const nlen = bits.need(5) + 257;
  const ndist = bits.need(5) + 1;
  const ncode = bits.need(4) + 4;
  if (nlen > MAX_LIT_CODES || ndist > MAX_DIST_CODES) fail("too many Huffman codes");
  const codeLengths = new Array(CODE_LENGTH_ORDER.length).fill(0);
  for (let i = 0; i < ncode; i++) codeLengths[CODE_LENGTH_ORDER[i]] = bits.need(3);
  const lencode = huffman(codeLengths);
  const lengths = [];
  while (lengths.length < nlen + ndist) {
    const sym = decode(bits, lencode);
    if (sym < 16) {
      lengths.push(sym);
      continue;
    }
    let repeat;
    let len = 0;
    if (sym === 16) {
      if (lengths.length === 0) fail("a repeat with no length before it");
      len = lengths[lengths.length - 1];
      repeat = 3 + bits.need(2);
    } else if (sym === 17) {
      repeat = 3 + bits.need(3);
    } else {
      repeat = 11 + bits.need(7);
    }
    if (lengths.length + repeat > nlen + ndist) fail("too many code lengths");
    for (let i = 0; i < repeat; i++) lengths.push(len);
  }
  if (lengths[END_OF_BLOCK] === 0) fail("no end-of-block code");
  return { lit: huffman(lengths.slice(0, nlen)), dist: huffman(lengths.slice(nlen)) };
}

function codes(bits, { lit, dist }) {
  for (;;) {
    let sym = decode(bits, lit);
    if (sym === END_OF_BLOCK) return;
    if (sym < END_OF_BLOCK) continue;
    sym -= END_OF_BLOCK + 1;
    if (sym >= LENGTH_EXTRA.length) fail("an invalid length code");
    bits.need(LENGTH_EXTRA[sym]);
    const dsym = decode(bits, dist);
    if (dsym >= DIST_EXTRA.length) fail("an invalid distance code");
    bits.need(DIST_EXTRA[dsym]);
  }
}

function stored(bits) {
  bits.align();
  const len = bits.need(16);
  const nlen = bits.need(16);
  if ((len ^ 0xffff) !== nlen) fail("a stored block's length does not match its complement");
  if (bits.pos + len > bits.bytes.length) fail("the deflate stream is cut short");
  bits.pos += len;
}

export function deflateEnd(bytes) {
  const bits = new Bits(bytes);
  let last = 0;
  while (!last) {
    last = bits.need(1);
    const type = bits.need(2);
    if (type === 0) stored(bits);
    else if (type === 1) codes(bits, fixedTables());
    else if (type === 2) codes(bits, dynamicTables(bits));
    else fail("an invalid block type");
  }
  return bits.pos;
}
