// The request beside a hash link (CONTRACT.md, The request file and pasted
// blocks): the link carries only h, a check of the request, and the person
// gives the page the request as the file their agent sent or as the text
// blocks it pasted. The shared cases are in api/mcp/links/request-file.json.
// h is a transfer check, not a trust anchor: once it matches, the text is
// read as a long link's fragment, with every check a long link gets.

export const HASH_PREFIX = "#h=";
export const MAX_REQUEST_FILE_BYTES = 4 * 1024 * 1024;
const PIECE_CHARS = 1800;
const MAX_BLOCKS = 10;
const HASH_BYTES = 16;

const LINE_BREAKS = /\r\n|[\n\r\u2028]/;
const MARKS = /[>*\\`]/g;
const EDGE_WHITESPACE = /^\p{White_Space}+|\p{White_Space}+$/gu;
const ALL_WHITESPACE = /\p{White_Space}/gu;
const HEADER = /(?:^|.* )basalt-request (\d+)\/(\d+) ([A-Za-z0-9_-]{22}) (\d+)$/;
const PIECE_LINE = /^[A-Za-z0-9_.-]+$/;
const BOM = "\uFEFF";

function base64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// requestHash is h: base64url of the first 16 bytes of sha256(text).
export async function requestHash(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return base64url(new Uint8Array(digest).slice(0, HASH_BYTES));
}

// readRequestFile reads a file's content against the link's h: the request
// text, or MISMATCH.
export async function readRequestFile(content, h) {
  let text = String(content ?? "");
  if (text.startsWith(BOM)) text = text.slice(BOM.length);
  text = text.replace(ALL_WHITESPACE, "");
  if ((await requestHash(text)) !== h) return { error: "MISMATCH" };
  return { text };
}

function cleanLine(line) {
  return line.replace(MARKS, "").replace(EDGE_WHITESPACE, "");
}

// parseBlocks reads the blocks of one paste, line by line: each header,
// then the piece lines after it up to its length.
function parseBlocks(paste) {
  const blocks = [];
  let cur = null;
  for (const line of String(paste ?? "").split(LINE_BREAKS)) {
    const clean = cleanLine(line);
    const m = HEADER.exec(clean);
    if (m) {
      cur = { i: Number(m[1]), n: Number(m[2]), h: m[3], size: Number(m[4]), piece: "", open: true };
      blocks.push(cur);
      continue;
    }
    if (cur === null || !cur.open || cur.piece.length >= cur.size) continue;
    if (!PIECE_LINE.test(clean)) {
      cur.open = false;
      continue;
    }
    cur.piece += clean;
  }
  return blocks;
}

// BlockAssembler is the paste box of a hash link: it keeps the blocks pasted
// so far for the link's h.
export class BlockAssembler {
  constructor(h) {
    this.h = h;
    this.n = 0;
    this.pieces = new Map();
  }

  // add reads one paste. It returns the reasons the page refused a block, or
  // of the paste itself: NO_BLOCK, CUT_SHORT, OTHER_REQUEST.
  add(paste) {
    const blocks = parseBlocks(paste);
    if (blocks.length === 0) return ["NO_BLOCK"];
    const refused = [];
    for (const b of blocks) {
      if (b.size < 1 || b.size > PIECE_CHARS || b.piece.length < b.size) {
        refused.push("CUT_SHORT");
        continue;
      }
      if (b.h !== this.h || b.i < 1 || b.i > b.n || b.n > MAX_BLOCKS || (this.n !== 0 && b.n !== this.n)) {
        refused.push("OTHER_REQUEST");
        continue;
      }
      this.n = b.n;
      this.pieces.set(b.i, b.piece.slice(0, b.size));
    }
    return refused;
  }

  // missing lists the block numbers not pasted yet; empty before the first.
  missing() {
    const out = [];
    for (let i = 1; i <= this.n; i++) if (!this.pieces.has(i)) out.push(i);
    return out;
  }

  // text joins the pieces once every block is in: the request text, or
  // INCOMPLETE, or MISMATCH when the joined text fails the h check.
  async text() {
    if (this.n === 0 || this.missing().length > 0) return { error: "INCOMPLETE" };
    let text = "";
    for (let i = 1; i <= this.n; i++) text += this.pieces.get(i);
    if ((await requestHash(text)) !== this.h) return { error: "MISMATCH" };
    return { text };
  }
}
