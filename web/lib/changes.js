// The Changes panel of the approval and revert pages: one table per table
// the rows are in, one line per row, columns across, a − or + in the first
// column. An update is two lines: the row before (−) and after (+), with the
// cells that change highlighted. Text only goes in through textContent.
import { displayValue, visibleText } from "./codec.js";
import { largeHash, largeInfo, tooLargeText } from "./large.js";
import { el } from "./page.js";
import { notChecked, OPEN_FROM_ENGINE, revealedLine } from "./reveal.js";

// HIDDEN_VALUE stands in for every value of a row hidden from the agent:
// never an empty cell.
export const HIDDEN_VALUE = "••••••";
export const HIDDEN_CHIP = "hidden from the agent";
export const SHOWN_CHIP = "shown to you only";

const MINUS = "−";

// display shows a column's value as the line carries it (displayValue), with
// the characters that hide or reorder text shown as escapes (visibleText).
export function display(line, member, col) {
  const text = rawText(line, member, col);
  const info = largeInfo(text);
  return info === null ? visibleText(text) : largeShown(text, info);
}

export function rawText(line, member, col) {
  const row = line[member] ?? {};
  return displayValue(row[col], line.texts?.[member]?.get(col));
}

// largeShown is what stands in for a value over 1 MiB of text: its size and
// sha256 (an ellipsis until the hash is computed) and the line saying the
// signature covers it (large.js).
function largeShown(text, info) {
  return tooLargeText(info.bytes, largeHash.cached(text) ?? "\u2026");
}

// rowKeyText names a row by its primary key, for a row with no values to
// show: "Row id = 42", or each key column for a composite key.
export function rowKeyText(line) {
  const key = line.key ?? {};
  const parts = Object.keys(key).map((col) => `${visibleText(col)} = ${display(line, "key", col)}`);
  return parts.length ? `Row ${parts.join(", ")}` : "Row key not recorded.";
}

// rowName is "Row id = 8" for a row with a key, else "This row".
function rowName(line) {
  return Object.keys(line.key ?? {}).length ? rowKeyText(line) : "This row";
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

// tableGroups groups items ({ line, index }) by table, cascaded rows apart,
// in the order the lines come.
export function tableGroups(items) {
  const groups = [];
  const byKey = new Map();
  for (const item of items) {
    const k = JSON.stringify([item.line.resource, item.line.cascaded]);
    let g = byKey.get(k);
    if (g === undefined) {
      g = { resource: item.line.resource, cascaded: item.line.cascaded, items: [] };
      byKey.set(k, g);
      groups.push(g);
    }
    g.items.push(item);
  }
  // The approval and the revert page list the same rows in the same order:
  // the table's own rows first, then cascaded ones, each by table name.
  return groups.sort((a, b) => Number(a.cascaded) - Number(b.cascaded) || compareText(a.resource, b.resource));
}

function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

const INTEGER = /^-?\d+$/;
const NUMBER = /^-?\d+(\.\d+)?([eE][-+]?\d+)?$/;

function compareValues(a, b) {
  if (INTEGER.test(a) && INTEGER.test(b)) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  if (NUMBER.test(a) && NUMBER.test(b)) return Number(a) - Number(b) || compareText(a, b);
  return compareText(a, b);
}

// compareRows orders rows by their key, column by column (numbers as
// numbers); a row whose key the page does not have yet (hidden) comes after,
// in line order.
function compareRows(x, y) {
  const kx = x.view.line.key;
  const ky = y.view.line.key;
  if (!kx || !ky) return Number(!kx) - Number(!ky) || x.index - y.index;
  for (const col of Object.keys(kx)) {
    const c = compareValues(display(x.view.line, "key", col), display(y.view.line, "key", col));
    if (c !== 0) return c;
  }
  return x.index - y.index;
}

// view is what the page shows of one line: its values, or, for a line hidden
// from the agent, the values the person revealed (shown) or none.
function view(line, shown, mid) {
  if (!line.redacted) return { line, hidden: false, checked: true, secret: new Set() };
  if (!shown) return { line, hidden: true, checked: true, secret: new Set() };
  return { line: revealedLine(line, shown, mid), hidden: false, checked: shown.checked, secret: new Set(shown.secretColumns) };
}

// sides is the row before and after the change. The approval page goes by
// the op: none before for an insert, none after for a delete. The revert
// page goes by what the line carries, as its row table always did: the row
// now when there is one (for a row it leaves alone whatever the op, so a
// re-insert whose key is taken, KEY_TAKEN, shows the row holding it), and
// what it goes back to unless it leaves the row alone.
function sides(line, mid, skipped) {
  if (mid === "now") return { before: line.now ?? null, after: skipped ? null : (line.set ?? null) };
  const before = line.op !== "INSERT" ? line[mid] : null;
  const after = line.op !== "DELETE" ? line.set : null;
  return { before: before ?? null, after: after ?? null };
}

// columnsOf is the group's columns: in the store's field order when the
// engine sent it (order, unsigned and for display only), any field it does
// not list after them in the order the rows carry; in the rows' order without it (a long
// link). Every column the rows carry is shown either way.
function columnsOf(views, mid, skipped, order = []) {
  const cols = new Set();
  for (const v of views) {
    if (v.hidden) continue;
    const { before, after } = sides(v.line, mid, skipped(v.line));
    for (const row of [v.line.key, before, after]) for (const c of Object.keys(row ?? {})) cols.add(c);
  }
  const listed = order.filter((c) => cols.has(c));
  const rest = [...cols].filter((c) => !listed.includes(c));
  return [...listed, ...rest];
}

// LONG_VALUE is the length, in characters, past which a value may wrap.
const LONG_VALUE = 32;

// cell is col's value in member, or in the key when member leaves the key
// out; empty when the row has no such column.
function cell(v, member, col, cls) {
  const has = (m) => v.line[m] !== null && v.line[m] !== undefined && Object.hasOwn(v.line[m], col);
  const from = has(member) ? member : has("key") ? "key" : null;
  if (from === null) return el("td", cls);
  const text = rawText(v.line, from, col);
  const info = largeInfo(text);
  if (info === null) {
    // A short value stays on one line; only a long one wraps (style.css).
    const shown = visibleText(text);
    const kinds = [v.secret.has(col) ? "secret" : "", [...shown].length > LONG_VALUE ? "long" : ""];
    return el("td", [cls, ...kinds].filter(Boolean).join(" "), shown);
  }
  // A value over 1 MiB of text shows by size and hash; the hash fills in
  // when the digest is done.
  const td = el("td", `${cls} large`.trim(), largeShown(text, info));
  largeHash(text).then((h) => {
    td.textContent = tooLargeText(info.bytes, h);
  });
  return td;
}

function tr(cls, marker) {
  const row = el("tr", cls);
  row.append(el("td", "mk", marker));
  return row;
}

const MARKS = { DELETE: MINUS, INSERT: "+", UPDATE: "±" };

// diffRows renders one line as table rows. highlights(v, col) says whether
// the update changes col.
function diffRows(v, columns, opts) {
  const { line } = v;
  const skipped = opts.skipped(line);
  const width = Math.max(columns.length, 1);
  if (v.hidden) {
    const row = tr(skipped ? "keep" : { DELETE: "del", INSERT: "add", UPDATE: "upd" }[line.op], skipped ? "=" : MARKS[line.op]);
    for (let i = 0; i < width; i++) row.append(el("td", "hidden-value", HIDDEN_VALUE));
    return [row];
  }
  const { before, after } = sides(line, opts.mid, skipped);
  if (before === null && after === null) {
    const row = tr("keep", "=");
    const td = el("td", "key", rowKeyText(line));
    td.colSpan = width;
    row.append(td);
    return [row];
  }
  if (skipped || after === null) {
    const row = tr(skipped ? "keep" : "del", skipped ? "=" : MINUS);
    for (const col of columns) row.append(cell(v, opts.mid, col, ""));
    return [row];
  }
  if (before === null) {
    const row = tr("add", "+");
    for (const col of columns) row.append(cell(v, "set", col, ""));
    return [row];
  }
  const was = tr("del", MINUS);
  const now = tr("add", "+");
  for (const col of columns) {
    const changes = Object.hasOwn(after, col) && opts.highlights(v, col);
    was.append(cell(v, opts.mid, col, changes ? "was" : ""));
    now.append(Object.hasOwn(after, col) ? cell(v, "set", col, changes ? "set" : "") : cell(v, opts.mid, col, ""));
  }
  return [was, now];
}

// groupTable is one group's rows as a table: a header row, then the rows.
// agentsCell is a row's "Changed by" cell, spanning the row's lines: a tag
// per agent opts.agents names for the line, empty when it names none.
function agentsCell(opts, line, span) {
  const cell = el("td", "who");
  cell.rowSpan = span;
  for (const who of opts.agents(line) ?? []) cell.append(opts.agentTag(who));
  return cell;
}

export function groupTable(views, opts) {
  const columns = columnsOf(views, opts.mid, opts.skipped, opts.order);
  const why = views.some((v) => opts.why(v.line) !== null);
  const table = el("table", "values");
  const head = el("tr");
  head.append(el("th", "mk", ""));
  if (opts.agents) head.append(el("th", "who", "Changed by"));
  if (columns.length === 0) head.append(el("th", "", "values"));
  for (const col of columns) head.append(el("th", "", visibleText(col)));
  if (why) head.append(el("th", "why", "Why"));
  table.append(head);
  for (const v of views) {
    const rows = diffRows(v, columns, opts);
    if (opts.agents) {
      const [mark, ...rest] = rows[0].children;
      rows[0].replaceChildren(mark, agentsCell(opts, v.line, rows.length), ...rest);
    }
    for (const row of rows) {
      if (why) row.append(el("td", "why", opts.why(v.line) ?? ""));
      if (!v.checked) row.className += " unchecked";
      table.append(row);
    }
  }
  return table;
}

// changeGroups renders items ({ line, index }) as one block per table.
// opts:
//   mid         the member holding the row before: "old" (approval) or "now" (revert)
//   shown       Map from line index to its revealed row
//   longLink    the page came from a long link (no reveal there)
//   who         the agent tag of every row, or null
//   agents      line => the agents of that row ({role, other}), or null; with
//               agentTag, a "Changed by" column instead of the group's tag
//   skipped     line => whether the revert leaves it alone
//   why         line => the reason it is left alone, or null
//   highlights  (view, col) => whether an update changes col
//   notes       lines => notes under the table, for the group's lines
//   fields      Map from resource to its field names in the store's order
//               (engine only)
export function changeGroups(items, opts) {
  return tableGroups(items).map((g) => {
    const views = g.items
      .map(({ line, index }) => ({ index, view: view(line, opts.shown.get(index), opts.mid) }))
      .sort(compareRows)
      .map((r) => r.view);
    const box = el("div", "group");
    const head = el("div", "group-head");
    head.append(el("span", "table-name", visibleText(g.resource)));
    head.append(el("span", "count", plural(g.items.length, "row")));
    if (g.cascaded) head.append(el("span", "tag", "cascaded"));
    const redacted = g.items.some(({ line }) => line.redacted);
    const hidden = views.some((v) => v.hidden);
    if (redacted) head.append(el("span", hidden ? "tag" : "tag shown", hidden ? HIDDEN_CHIP : SHOWN_CHIP));
    if (opts.who) head.append(opts.who());
    box.append(head);
    if (hidden && opts.longLink) box.append(el("p", "group-note", OPEN_FROM_ENGINE));
    const scroll = el("div", "scroll");
    scroll.append(groupTable(views, { ...opts, order: opts.fields?.get(g.resource) ?? [] }));
    box.append(scroll);
    for (const text of opts.notes(g.items.map((i) => i.line))) box.append(el("p", "group-note", text));
    for (const v of views) {
      if (!v.checked) box.append(el("p", "callout", notChecked(rowName(v.line))));
    }
    return box;
  });
}

// countText is the Changes panel's count: "−3 rows", "+2 rows", "±1 row",
// for each kind of change in lines.
export function countText(lines, opOf = (l) => l.op) {
  const counts = { DELETE: 0, INSERT: 0, UPDATE: 0 };
  // An op outside these three is not counted (no row of the page has one).
  for (const l of lines) if (Object.hasOwn(counts, opOf(l))) counts[opOf(l)] += 1;
  return ["DELETE", "INSERT", "UPDATE"]
    .filter((op) => counts[op] > 0)
    .map((op) => ({ op, text: `${MARKS[op]}${plural(counts[op], "row")}` }));
}
