// Repair of links a chat or a terminal wrapped (CONTRACT.md, Showing links,
// The pages repair what they can). The shared cases are in
// api/mcp/links/link-repair.json. Only the fragment is ever taken from pasted
// text: the page keeps its own origin and path and never navigates to or
// fetches a pasted URL.

const ENCODED_BREAKS = /%(?:20|09|0a|0d)/gi;
// Unicode White_Space, not JavaScript \s (which differs); plus the marks a
// quote, emphasis or Markdown escape leaves in a link.
const WHITESPACE_AND_MARKS = /[\p{White_Space}>*\\]/gu;
const LONG_PREFIX = /^[12]\.[A-Za-z0-9_-]*/;
const SHORT_LINK = /^[sh]=[A-Za-z0-9_-]{22}/;
const PASTE_START = /#([12]\.|s=|h=)/;
const SECRET_LENGTH = 22;
const BASE64URL_LINE = /^[A-Za-z0-9_-]+$/;
const BASE64URL_RUN = /^[A-Za-z0-9_-]*/;
const LINE_BREAKS = /\r\n|[\n\r\u2028]/;
const MARKS = /[>*\\]/g;
const EDGE_WHITESPACE = /^\p{White_Space}+|\p{White_Space}+$/gu;
// A short link's secret and a hash link's h are both 22 characters.
const FIXED_PREFIXES = new Set(["s=", "h="]);

// repairFragment repairs the text after the first # of a link.
export function repairFragment(text) {
  const clean = String(text ?? "").replace(ENCODED_BREAKS, "").replace(WHITESPACE_AND_MARKS, "");
  const long = LONG_PREFIX.exec(clean);
  if (long) return long[0];
  const short = SHORT_LINK.exec(clean);
  if (short) return short[0];
  return clean;
}

// repairHash repairs window.location.hash and returns it with its #. The
// text after the first # is the fragment, so a second # ends it.
export function repairHash(hash) {
  const text = String(hash ?? "");
  const rest = text.slice(text.indexOf("#") + 1);
  const end = rest.indexOf("#");
  return `#${repairFragment(end < 0 ? rest : rest.slice(0, end))}`;
}

// readPaste reads the fragment (without #) out of a pasted message, joining a
// link a client wrapped, or returns null when the text holds no link.
export function readPaste(text) {
  const lines = String(text ?? "")
    .split(LINE_BREAKS)
    .map((line) => line.replace(MARKS, "").replace(EDGE_WHITESPACE, ""));
  const first = lines.findIndex((line) => PASTE_START.test(line));
  if (first < 0) return null;
  const start = PASTE_START.exec(lines[first]);
  const prefix = start[1];
  const tail = lines[first].slice(start.index + 1 + prefix.length);
  const run = BASE64URL_RUN.exec(tail)[0];
  let found = run;
  if (run.length === tail.length) {
    // The link reached the end of its line: a wrapped link goes on in the
    // lines that follow, until an empty line or one that is not all base64url.
    for (const next of lines.slice(first + 1)) {
      if (!BASE64URL_LINE.test(next)) break;
      found += next;
    }
  }
  if (FIXED_PREFIXES.has(prefix)) found = found.slice(0, SECRET_LENGTH);
  return repairFragment(prefix + found);
}
