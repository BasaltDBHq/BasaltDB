// The Changes panel of the approval and revert pages: one table per table
// the rows are in, one line per row, columns across, a − or + in the first
// column. An update is two lines: the row before (−) and after (+), with the
// cells that change highlighted. Text only goes in through textContent.
import { displayValue, visibleText } from "./codec.js";
import { el } from "./page.js";
import { NOT_CHECKED, OPEN_FROM_ENGINE, revealedLine } from "./reveal.js";

// HIDDEN_VALUE stands in for every value of a row hidden from the agent:
// never an empty cell.
export const HIDDEN_VALUE = "••••••";
export const HIDDEN_CHIP = "hidden from the agent";
export const SHOWN_CHIP = "shown to you only";

const MINUS = "−";

// display shows a column's value as the line carries it (displayValue), with
// the characters that hide or reorder text shown as escapes (visibleText).
export function display(line, member, col) {
  const row = line[member] ?? {};
  return visibleText(displayValue(row[col], line.texts?.[member]?.get(col)));
}

// rowKeyText names a row by its primary key, for a row with no values to
// show: "Row id = 42", or each key column for a composite key.
export function rowKeyText(line) {
  const key = line.key ?? {};
  const parts = Object.keys(key).map((col) => `${visibleText(col)} = ${display(line, "key", col)}`);
  return parts.length ? `Row ${parts.join(", ")}` : "Row key not recorded.";
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
    const k = JSON.stringify([item.line.table, item.line.cascaded]);
    let g = byKey.get(k);
    if (g === undefined) {
      g = { table: item.line.table, cascaded: item.line.cascaded, items: [] };
      byKey.set(k, g);
      groups.push(g);
    }
    g.items.push(item);
  }
  return groups;
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

function columnsOf(views, mid, skipped) {
  const cols = new Set();
  for (const v of views) {
    if (v.hidden) continue;
    const { before, after } = sides(v.line, mid, skipped(v.line));
    for (const row of [v.line.key, before, after]) for (const c of Object.keys(row ?? {})) cols.add(c);
  }
  return [...cols];
}

// cell is col's value in member, or in the key when member leaves the key
// out; empty when the row has no such column.
function cell(v, member, col, cls) {
  const has = (m) => v.line[m] !== null && v.line[m] !== undefined && Object.hasOwn(v.line[m], col);
  const from = has(member) ? member : has("key") ? "key" : null;
  if (from === null) return el("td", cls);
  return el("td", v.secret.has(col) ? `${cls} secret`.trim() : cls, display(v.line, from, col));
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
export function groupTable(views, opts) {
  const columns = columnsOf(views, opts.mid, opts.skipped);
  const why = views.some((v) => opts.why(v.line) !== null);
  const table = el("table", "values");
  const head = el("tr");
  head.append(el("th", "mk", ""));
  if (columns.length === 0) head.append(el("th", "", "values"));
  for (const col of columns) head.append(el("th", "", visibleText(col)));
  if (why) head.append(el("th", "why", "Why"));
  table.append(head);
  for (const v of views) {
    for (const row of diffRows(v, columns, opts)) {
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
//   skipped     line => whether the revert leaves it alone
//   why         line => the reason it is left alone, or null
//   highlights  (view, col) => whether an update changes col
//   notes       lines => notes under the table, for the group's lines
export function changeGroups(items, opts) {
  return tableGroups(items).map((g) => {
    const views = g.items.map(({ line, index }) => view(line, opts.shown.get(index), opts.mid));
    const box = el("div", "group");
    const head = el("div", "group-head");
    head.append(el("span", "table-name", visibleText(g.table)));
    head.append(el("span", "count", plural(g.items.length, "row")));
    if (g.cascaded) head.append(el("span", "tag", "cascaded"));
    const redacted = g.items.some(({ line }) => line.redacted);
    const hidden = views.some((v) => v.hidden);
    if (redacted) head.append(el("span", hidden ? "tag" : "tag shown", hidden ? HIDDEN_CHIP : SHOWN_CHIP));
    if (opts.who) head.append(opts.who());
    box.append(head);
    if (hidden && opts.longLink) box.append(el("p", "group-note", OPEN_FROM_ENGINE));
    const scroll = el("div", "scroll");
    scroll.append(groupTable(views, opts));
    box.append(scroll);
    for (const text of opts.notes(g.items.map((i) => i.line))) box.append(el("p", "group-note", text));
    for (const v of views) {
      if (!v.checked) box.append(el("p", "callout", `${rowKeyText(v.line)}. ${NOT_CHECKED}`));
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
