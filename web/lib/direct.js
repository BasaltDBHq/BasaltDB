// The DIRECT transport (CONTRACT.md, Direct transport): the portal page
// reaches the person's engine straight through their own tunnel, at an
// address this device pinned by hand, and runs the link session there.
// The page tries each pin, the one that last opened a session first: it
// probes GET <address>/v1/engine, and only when the key it answers with is
// the pinned one opens wss://<host>/v1/session. Every handshake checks the
// engine's key against the pin again, so a wrong or hijacked address can
// deny service but never read or forge.

import { ChannelError, DIRECT, engineIdOf, fingerprint, openChannel, parseEngineKey } from "./channel.js";
import { PORTAL } from "./codec.js";
import { socketOrigin } from "./engineaddr.js";
import { byLastUse } from "./pins.js";
import { RelayError, SECRET_HEADER } from "./local.js";

export const PROBE_MS = 5000;

// Outcomes of trying one pin.
const REFUSED = "LINK_REFUSED";
const REVOKED = "ENGINE_REVOKED";
const KEY_CHANGED = "ENGINE_KEY_CHANGED";
const UNREACHABLE = "UNREACHABLE";

const PIN_PAGE = `${PORTAL}/engines/add`;
const ENGINES_PAGE = `${PORTAL}/engines`;
const GO_ON =
  `To go on: add your engine on this device (${PIN_PAGE}), ask the agent for the link again, ` +
  "or use the long link (basalt approve or basalt revert on your own computer, or list_pending in the agent).";

// probe asks an address which engine answers there (GET /v1/engine, no
// credentials, no cache, 5 seconds). It resolves with the answer's JSON
// object, untrusted, or "" when the address does not answer as an engine.
export async function probe(fetchFn, address, ms = PROBE_MS) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), ms);
  try {
    const res = await fetchFn(`${address}/v1/engine`, {
      method: "GET",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: ctl.signal,
    });
    if (res.status !== 200) return "";
    const body = await res.json();
    return body !== null && typeof body === "object" && !Array.isArray(body) ? body : "";
  } catch {
    return "";
  } finally {
    clearTimeout(timer);
  }
}

// checkEngineAnswer checks a probe's answer (direct-engine.schema.json):
// exactly engineKey and engineId, the key a P-256 SPKI, and the id that
// key's id. It resolves with { engineKey, engineId, fingerprint }, or null
// for anything else. Nothing trusts this answer alone: the person compares
// the fingerprint by hand, and every session checks the key again.
export async function checkEngineAnswer(answer) {
  if (answer === null || typeof answer !== "object" || Array.isArray(answer)) return null;
  if (Object.keys(answer).sort().join(",") !== "engineId,engineKey") return null;
  const { engineKey, engineId } = answer;
  if (typeof engineKey !== "string" || typeof engineId !== "string") return null;
  if ((await parseEngineKey(engineKey)) === null) return null;
  if ((await engineIdOf(engineKey)) !== engineId) return null;
  return { engineKey, engineId, fingerprint: fingerprint(engineId) };
}

// failure is what the page says when no pin opened a session for the link.
export function failure(pins, outcomes) {
  if (pins.length === 0) {
    return new RelayError(
      "this device has no engine pinned",
      "UNAVAILABLE",
      0,
      {
        personMessage: `This page reaches your engine through your own tunnel, and this device has not pinned one yet. ${GO_ON}`,
      },
    );
  }
  const lines = [];
  for (const { address, outcome } of outcomes) {
    if (outcome === KEY_CHANGED) {
      lines.push(
        `${address} now answers with a different engine than the one this device pinned. Check with basalt engine list --admin ` +
          "on your own computer before pinning it again.",
      );
    }
    if (outcome === REVOKED) {
      lines.push(
        `The engine at ${address} may have been revoked. Check with basalt engine list --admin on your own computer; ` +
          `you can remove its pin on ${ENGINES_PAGE}.`,
      );
    }
  }
  const refused = outcomes.filter((o) => o.outcome === REFUSED).length;
  if (refused > 0 && lines.length === 0) {
    return new RelayError("no pinned engine holds this link", "NOT_FOUND", 0, {
      reason: "LINK",
      personMessage: `Your pinned engine does not hold this link: it expired, was replaced by a newer one, or was made by another engine. ${GO_ON}`,
    });
  }
  lines.unshift("This link could not reach your engine through your tunnel.");
  lines.push(GO_ON);
  return new RelayError("cannot reach the engine through the tunnel", "UNAVAILABLE", 0, { personMessage: lines.join("\n") });
}

// sessionLost is the error of a request whose new session did not open: a
// refused link or a revoked engine is final (an answer, not retried); any
// other failure is left for the caller to retry.
function sessionLost(err, pin) {
  if (err?.code === "LINK_REFUSED" || err?.code === "LINK") {
    return new RelayError("the engine no longer holds this link", "NOT_FOUND", 0, { reason: "LINK" });
  }
  if (err?.code === "ENGINE_REVOKED" || err?.code === "ENGINE_KEY_CHANGED") return failure([pin], [{ address: pin.address, outcome: err.code }]);
  return err;
}

// DirectSession keeps one link session to the pinned engine that opened it.
// When that session ends (the engine closes an idle one), the next request
// opens a new one to the same pin with the secret it carries: after a widen
// that is the link's new secret.
class DirectSession {
  constructor(pin, channel, connect) {
    this.pin = pin;
    this.channel = channel;
    this.connect = connect;
    this.closed = false;
    this.transport = DIRECT;
    this.engine = { address: pin.address, engineId: pin.engineId };
  }

  async request(method, path, headers = {}, body = null) {
    if (this.closed) throw new Error("this session to the engine is closed");
    const secret = headers[SECRET_HEADER] ?? "";
    if (this.channel === null || this.channel.ended !== null) {
      this.channel = null;
      try {
        this.channel = await this.connect(this.pin, secret);
      } catch (err) {
        throw sessionLost(err, this.pin);
      }
    }
    const sent = { ...headers, origin: PORTAL };
    const res = await this.channel.request(method, path, sent, body ?? "");
    return res;
  }

  close() {
    this.closed = true;
    this.channel?.close();
  }
}

// directTransport opens link sessions over this device's pins. store is a
// pin store (pins.js); fetchFn and socket reach the network (transport.js
// passes the browser's). When the pins cookie does not list this device's
// pins, the page's CSP was built without them: open rewrites the cookie and
// calls onStaleCookie, which reloads the page (true) or lets it go on.
// onOpened runs once a session opened.
export function directTransport({ store, fetchFn, socket, probeMs = PROBE_MS, onStaleCookie = () => false, onOpened = () => {}, open = openChannel }) {
  const connect = (pin, secret) => open(() => socket(`${socketOrigin(pin.address)}/v1/session`), { transport: DIRECT, secret, expectEngineId: pin.engineId });

  return {
    kind: DIRECT,
    async open(link) {
      if (!store.inCookie()) {
        store.syncCookie();
        // The page reloads with a CSP that lists the pins.
        if (onStaleCookie()) return new Promise(() => {});
      }
      const pins = byLastUse(store.list());
      const outcomes = [];
      for (const pin of pins) {
        const answer = await probe(fetchFn, pin.address, probeMs);
        const key = typeof answer === "object" && typeof answer.engineKey === "string" ? answer.engineKey : "";
        if (key === "") {
          outcomes.push({ address: pin.address, outcome: UNREACHABLE });
          continue;
        }
        if (key !== pin.engineKey) {
          outcomes.push({ address: pin.address, outcome: KEY_CHANGED });
          continue;
        }
        try {
          const channel = await connect(pin, link.secret);
          store.touch(pin.address);
          onOpened();
          return new DirectSession(pin, channel, connect);
        } catch (err) {
          if (!(err instanceof ChannelError)) throw err;
          if (err.code === "LINK") throw new RelayError(err.message, "NOT_FOUND", 0, { reason: "LINK" });
          const outcome = { LINK_REFUSED: REFUSED, ENGINE_REVOKED: REVOKED, ENGINE_KEY_CHANGED: KEY_CHANGED }[err.code] ?? UNREACHABLE;
          outcomes.push({ address: pin.address, outcome });
        }
      }
      throw failure(pins, outcomes);
    },
  };
}
