// The page pieces the connect page and the local setup page share: one
// column's label picker (CONTRACT.md, Column labels on the connect page).
import { ENTITY_WORDS, FIXED_WORDS, labelOf, tableName } from "./picks.js";

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

// labelRow is one column with its label: a native select (blank only on
// a column without a class), a country box for a phone, and for a class
// the page does not offer (PUBLIC, FREE_TEXT) a fixed label with "change".
// labels holds the choices (current and set); onChange runs after each.
// suggestion (suggestionOf on the setup page, null on the connect page)
// marks the suggested option and is never chosen by itself.
export function labelRow(c, labels, onChange, suggestion = null) {
  const row = el("div", "label-row");
  const name = `${tableName(c.table)}.${c.column}`;
  row.appendChild(el("span", "mono col-name", c.column));
  const was = labelOf(c);
  const now = labels.current(c);
  const pick = el("select");
  pick.setAttribute("aria-label", `Label for ${name}`);
  const region = el("input", "text region");
  region.type = "text";
  region.maxLength = 2;
  region.autocomplete = "off";
  region.placeholder = "US";
  region.setAttribute("aria-label", `Country of the phone numbers in ${name}, two letters`);
  region.hidden = true;
  const fixed = was.class === "PUBLIC" || was.class === "FREE_TEXT";
  // The suggestion, when there is one the picker offers, is marked on its
  // option; it is chosen only when the person picks it.
  const suggested = suggestion?.label.class === "IDENTIFIER" ? `IDENTIFIER:${suggestion.label.entityType}` : suggestion?.label.class === "SECRET" ? "SECRET" : "";
  const option = (parent, value, text) => {
    const o = el("option", "", value !== "" && value === suggested ? `${text} (suggested)` : text);
    o.value = value;
    parent.appendChild(o);
  };
  if (was.class === "UNCLASSIFIED") option(pick, "", "—");
  if (fixed) {
    const o = el("option", "", "Choose a label");
    o.value = "";
    o.disabled = true;
    pick.appendChild(o);
  }
  const personal = el("optgroup");
  personal.label = "Personal";
  for (const [entity, words] of Object.entries(ENTITY_WORDS)) option(personal, `IDENTIFIER:${entity}`, `Personal: ${words}`);
  if (was.class === "IDENTIFIER" && was.entityType && !ENTITY_WORDS[was.entityType]) option(personal, `IDENTIFIER:${was.entityType}`, `Personal: ${was.entityType.toLowerCase()}`);
  const other = suggestion?.label.entityType;
  if (suggested.startsWith("IDENTIFIER:") && !ENTITY_WORDS[other] && other !== was.entityType) option(personal, suggested, `Personal: ${other.toLowerCase()}`);
  pick.appendChild(personal);
  option(pick, "SECRET", "Secret");
  pick.value = now.class === "IDENTIFIER" ? `IDENTIFIER:${now.entityType}` : now.class === "SECRET" ? "SECRET" : "";
  region.value = now.phoneRegion;
  const update = () => {
    const v = pick.value;
    region.hidden = v !== "IDENTIFIER:PHONE";
    if (v === "IDENTIFIER:PHONE" && v === suggested && region.value === "" && suggestion.label.phoneRegion) region.value = suggestion.label.phoneRegion;
    if (v === "") {
      if (was.class === "UNCLASSIFIED") labels.set(c.table, c.column, null);
    } else if (v === "SECRET") {
      labels.set(c.table, c.column, { class: "SECRET" });
    } else {
      const entityType = v.slice("IDENTIFIER:".length);
      labels.set(c.table, c.column, { class: "IDENTIFIER", entityType, phoneRegion: entityType === "PHONE" ? region.value.trim().toUpperCase() : "" });
    }
    onChange();
  };
  pick.addEventListener("change", update);
  region.addEventListener("input", update);
  region.hidden = pick.value !== "IDENTIFIER:PHONE";
  // The picker sits at the row's right edge in a column of one width, with
  // the country box and the suggestion under it; a class the picker does
  // not offer shows there as a fixed label with "change".
  const box = el("span", "label-pick");
  if (fixed) {
    const line = el("span", "label-fixed-line");
    const label = el("span", "label-fixed", FIXED_WORDS[was.class]);
    const change = el("button", "link", "change");
    change.type = "button";
    change.setAttribute("aria-label", `Change the label of ${name}`);
    const changed = now.class !== was.class;
    pick.hidden = !changed;
    line.hidden = changed;
    change.addEventListener("click", () => {
      line.hidden = true;
      pick.hidden = false;
    });
    line.appendChild(label);
    line.appendChild(change);
    box.appendChild(line);
  }
  box.appendChild(pick);
  box.appendChild(region);
  if (suggestion) box.appendChild(el("span", "label-suggested", `Suggested: ${suggestion.words}`));
  row.appendChild(box);
  return row;
}
