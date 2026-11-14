// The pin page (CONTRACT.md, Direct transport, The pin page; OR-6):
// /engines/add pins the person's engine on this device, /engines lists the
// pins and removes one. Pinning works only on the portal.
//
// The page cannot reach an address its CSP does not list, and the portal's
// edge function lists only what the request names: so Check this address
// loads /engines/add?address=<address>, whose CSP allows that one https
// origin (web/edge/portal.js), and the page then asks it which engine
// answers. Nothing is pinned until the person confirms the fingerprint.

import { PORTAL } from "./codec.js";
import { parseEngineAddress } from "./engineaddr.js";
import { checkEngineAnswer, probe } from "./direct.js";
import { $, el, fail, whenText } from "./page.js";
import { PinError, byLastUse, pinStore } from "./pins.js";
import { browserFetch } from "./transport.js";
import { fingerprint } from "./channel.js";

const ADD_PATH = "/engines/add";
const BAD_ADDRESS =
  "Give the address as https://<host> or https://<host>:<port>: a lowercase public name, no path, not an IP address, " +
  "not localhost or a local network name.";
const NO_ANSWER =
  "No engine answered at this address. Check that the tunnel is up and forwards to the engine's direct listener " +
  "(basalt init --direct-addr), then try again.";

function showList(store) {
  const pins = byLastUse(store.list());
  $("none").hidden = pins.length > 0;
  $("pins").replaceChildren(
    ...pins.map((p) => {
      const row = el("li", "row");
      const title = el("div", "row-title");
      title.append(el("code", "", p.address), el("span", "muted", fingerprint(p.engineId)));
      const used = p.lastUsedAt ? `last used ${whenText(new Date(p.lastUsedAt), new Date())}` : "not used yet";
      const remove = el("button", "secondary", "Remove");
      remove.type = "button";
      remove.addEventListener("click", () => {
        if (!window.confirm(`Remove ${p.address} from this device? Links then stop opening through it here until you add it again.`)) return;
        store.remove(p.address);
        $("list-status").textContent = `Removed ${p.address}.`;
        showList(store);
      });
      row.append(title, el("p", "muted", `Added ${whenText(new Date(p.addedAt), new Date())}, ${used}.`), remove);
      return row;
    }),
  );
}

async function showCandidate(store, address) {
  $("address").value = address;
  $("add-status").textContent = "Asking the address which engine answers...";
  const engine = await checkEngineAnswer(await probe(browserFetch, address));
  if (engine === null) {
    $("add-status").textContent = NO_ANSWER;
    return;
  }
  $("add-status").textContent = "";
  $("confirm-address").textContent = address;
  $("confirm-fingerprint").textContent = engine.fingerprint;
  $("confirm").hidden = false;
  $("pin").addEventListener("click", () => {
    try {
      store.add({ address, engineKey: engine.engineKey, engineId: engine.engineId });
    } catch (err) {
      $("confirm-status").textContent = err instanceof PinError ? err.message : String(err?.message ?? err);
      return;
    }
    $("pin").disabled = true;
    $("confirm-status").textContent = "Added. Approval and revert links on this device now open through this engine.";
    showList(store);
  });
  $("cancel").addEventListener("click", () => window.location.assign(ADD_PATH));
}

function wireAdd(store) {
  $("add").hidden = false;
  const go = () => {
    const address = parseEngineAddress($("address").value.trim());
    if (address === null) {
      $("add-status").textContent = BAD_ADDRESS;
      return;
    }
    window.location.assign(`${ADD_PATH}?address=${encodeURIComponent(address)}`);
  };
  $("check").addEventListener("click", go);
  $("address").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") go();
  });
}

async function main() {
  if (window.location.origin !== PORTAL) {
    fail(`Engines are pinned only on ${PORTAL}.`);
    return;
  }
  const store = pinStore();
  // Keep the cookie in step with the pins, so the next page's CSP lists
  // exactly them.
  if (!store.inCookie()) store.syncCookie();
  $("main").hidden = false;
  showList(store);
  if (window.location.pathname !== ADD_PATH) {
    $("add-link").hidden = false;
    return;
  }
  wireAdd(store);
  const params = new URLSearchParams(window.location.search);
  if (!params.has("address")) return;
  const address = parseEngineAddress(params.get("address"));
  if (address === null || params.getAll("address").length !== 1) {
    $("add-status").textContent = BAD_ADDRESS;
    return;
  }
  await showCandidate(store, address);
}

main();
