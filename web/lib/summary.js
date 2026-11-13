// What a held write changes, counted from its bound preview lines (owner
// decision, Nov 12): the headline at the top of the approval page and the
// extra confirmation cascades need before the passkey prompt. The headline
// is the same text `basalt approve --show` prints
// (internal/approval/summary.go). Redacted lines count like any other: the
// counts are exact even when the values are hidden.

const VERBS = { INSERT: "insert", UPDATE: "update", DELETE: "delete" };
const PAST_VERBS = { INSERT: "inserted", UPDATE: "updated", DELETE: "deleted" };
const HIDDEN_MARK = " [values hidden]";

function addRow(groups, line) {
  const g = groups.find((x) => x.table === line.table && x.op === line.op);
  if (g) {
    g.rows++;
    g.hidden = g.hidden || line.redacted;
    return;
  }
  groups.push({ table: line.table, op: line.op, rows: 1, hidden: line.redacted });
}

// Byte order, like Go's string comparison.
function compareText(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

// summarize counts parsed preview lines (codec.js parseLine): direct groups
// in line order, cascaded groups most rows first, then by table and op.
export function summarize(lines) {
  const direct = [];
  const cascaded = [];
  for (const line of lines) addRow(line.cascaded ? cascaded : direct, line);
  cascaded.sort((a, b) => b.rows - a.rows || compareText(a.table, b.table) || compareText(a.op, b.op));
  const cascadedRows = cascaded.reduce((n, g) => n + g.rows, 0);
  return { direct, cascaded, cascadedRows };
}

function plural(n, noun) {
  return n === 1 ? `1 ${noun}` : `${n} ${noun}s`;
}

function capitalize(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function hidden(g) {
  return g.hidden ? HIDDEN_MARK : "";
}

// headline states the held write in one line, cascades explicit, e.g.
// "Delete 1 row in public.customers + 30 cascaded rows (public.invoices 28,
// public.payments 2 [values hidden])".
export function headline(summary) {
  const text = capitalize(
    summary.direct.map((g) => `${VERBS[g.op]} ${plural(g.rows, "row")} in ${g.table}${hidden(g)}`).join(", "),
  );
  if (summary.cascaded.length === 0) return text;
  const mainOp = summary.direct.length > 0 ? summary.direct[0].op : "";
  const entries = summary.cascaded.map((g) => {
    const verb = g.op === mainOp ? "" : ` ${PAST_VERBS[g.op]}`;
    return `${g.table} ${g.rows}${verb}${hidden(g)}`;
  });
  const cascade = `${plural(summary.cascadedRows, "cascaded row")} (${entries.join(", ")})`;
  if (text === "") return capitalize(cascade);
  return `${text} + ${cascade}`;
}

function listTables(tables) {
  if (tables.length === 1) return tables[0];
  return `${tables.slice(0, -1).join(", ")} and ${tables[tables.length - 1]}`;
}

// cascadeConfirmation is the sentence the person ticks before a write with
// cascaded rows can be signed, or null when nothing cascades.
export function cascadeConfirmation(summary) {
  if (summary.cascadedRows === 0) return null;
  const verb = summary.cascaded.every((g) => g.op === "DELETE") ? "deletes" : "changes";
  const tables = [...new Set(summary.cascaded.map((g) => g.table))];
  return `I understand this also ${verb} ${plural(summary.cascadedRows, "cascaded row")} in ${listTables(tables)}.`;
}

// canStartPasskey: an expired approval never; a write with cascaded rows
// only once the person confirmed them; anything else right away.
export function canStartPasskey({ summary, confirmed, expired }) {
  if (expired) return false;
  return summary.cascadedRows === 0 || confirmed === true;
}
