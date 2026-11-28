// The RELAY transport (CONTRACT.md, Vault channel: Link secrets in a
// session, The page's socket): on the portal, a short link's page reaches
// its engine through the hosted Vault. The page opens
// wss://relay.basaltvault.app/v1/links/<linkToken> and runs the link
// session (channel.js) on it, end to end with the engine: the Vault only
// forwards bytes it cannot read. The socket path carries linkToken and
// nothing else; the link secret travels only inside the session, as
// basalt-link-secret, and neither it nor psk nor a session key is logged
// or stored.
//
// It takes the browser's WebSocket as an argument (transport.js holds the
// browser's network calls), so tests run it against a fake or a real Vault.

import { ChannelError, MAX_REQUESTS, RELAY, fingerprint, openChannel } from "./channel.js";
import { PORTAL } from "./codec.js";
import { RelayError, SECRET_HEADER } from "./local.js";

// RELAY_ORIGIN is the Vault's address, compiled in as the portal's own
// origin is, and the only one the portal's CSP lets a page connect to.
export const RELAY_ORIGIN = "wss://relay.basaltvault.app";

// linkSocketURL is the page's socket for a link token (base64url text).
export function linkSocketURL(tokenText) {
  return `${RELAY_ORIGIN}/v1/links/${tokenText}`;
}

// The engine closes a session idle for 5 minutes (CONTRACT.md, Limits). A
// POST is never sent twice, so one that could meet that close in flight
// goes on a fresh session instead: past STALE_MS idle, the channel is
// opened again before a POST. A GET may simply be read again.
export const STALE_MS = 4 * 60 * 1000;

// The request headers a session carries besides origin (CONTRACT.md,
// Frames, Requests): any other header is answered 400, so none is sent.
const SENT_HEADERS = [SECRET_HEADER, "content-type"];

const LONG_LINK = "Ask the agent for a new link.";

// What the page shows for each way a session ends (CONTRACT.md, Close
// codes, "The page shows"). A code from the Vault decides only this text.
const LINK_GONE = new Set(["LINK", "LINK_REFUSED", "LINK_UNKNOWN"]);
const ENGINE_OFFLINE = new Set(["ENGINE_OFFLINE", "ENGINE_SHUTDOWN", "ENGINE_REVOKED"]);
const TRY_LATER = new Set(["RATE_LIMITED", "SESSION_LIMIT", "TIMEOUT"]);

export const VAULT_UNREACHABLE = `This page cannot reach the BasaltVault (relay.basaltvault.app), which carries it to your engine. ${LONG_LINK}`;
export const ENGINE_NOT_CONNECTED =
  `Your engine is not connected to the BasaltVault right now. Ask the agent to check its status, then ask it for a new link.`;
export const BUSY = "Your engine or the BasaltVault is busy. Wait a minute and open the link again. " + LONG_LINK;
export const ENGINE_CHANGED =
  "The engine answered this link with a different key than the one this page showed you, so the page stopped. Open the link again and " +
  "compare the fingerprint with the one the agent showed you in the chat before you sign.";

function broken(code) {
  return `The secure session to your engine failed (${code}), and this page used nothing from it. Open the link again. If it keeps failing: ${LONG_LINK}`;
}

// terminal turns a session's end into the RelayError the page shows, for
// the ends a retry cannot fix; null for the ones a new session may (a
// dropped socket, a broken frame, a session that reached its limit).
function terminal(err) {
  const code = err?.code ?? "";
  if (LINK_GONE.has(code)) return new RelayError("the engine no longer holds this link", "NOT_FOUND", 0, { reason: "LINK" });
  if (ENGINE_OFFLINE.has(code)) return new RelayError("the engine is not connected to the Vault", "UNAVAILABLE", 0, { personMessage: ENGINE_NOT_CONNECTED });
  return null;
}

// openFailure is what the page shows when a session cannot be opened at
// all. Every one is a RelayError, so the pages' retry loop stops on it.
export function openFailure(err) {
  const known = terminal(err);
  if (known !== null) return known;
  const code = err instanceof ChannelError ? err.code : "CONNECTION_FAILED";
  if (code === "CONNECTION_FAILED") return new RelayError("cannot reach the Vault", "UNAVAILABLE", 0, { personMessage: VAULT_UNREACHABLE });
  if (TRY_LATER.has(code)) return new RelayError("the Vault or the engine is busy", "UNAVAILABLE", 0, { personMessage: BUSY });
  return new RelayError(`the session to the engine failed (${code})`, "UNAVAILABLE", 0, { personMessage: broken(code) });
}

// sentHeaders are the headers a request carries in the session: the
// contract's set, from the portal's origin.
function sentHeaders(headers) {
  const out = {};
  for (const name of SENT_HEADERS) {
    if (typeof headers?.[name] === "string") out[name] = headers[name];
  }
  out.origin = PORTAL;
  return out;
}

// RelaySession is the pages' session over the Vault. One request is in
// flight at a time (the contract's rule): requests wait their turn. A
// channel that ended (idle for 5 minutes, dropped) or used its 64 requests,
// or that is close to its idle close before a POST (STALE_MS), is opened
// again before the next request is sent, never in the middle of
// one, so a POST is never sent twice. The secret for that comes from the
// request's own basalt-link-secret, never from the link the page opened
// with: after a widen the revert's secret is the new one.
class RelaySession {
  constructor(channel, connect, now) {
    this.channel = channel;
    this.connect = connect;
    this.now = now;
    this.usedAt = now();
    this.closed = false;
    this.transport = RELAY;
    this.engine = { engineId: channel.engineId, engineKey: channel.engineKey, fingerprint: fingerprint(channel.engineId) };
    this.queue = Promise.resolve();
  }

  request(method, path, headers = {}, body = null) {
    const run = this.queue.then(() => this.exchange(method, path, headers, body));
    this.queue = run.catch(() => {});
    return run;
  }

  async exchange(method, path, headers, body) {
    if (this.closed) throw new RelayError("this session to the engine is closed", "CLOSED");
    const spent = this.channel !== null && this.channel.nextId >= MAX_REQUESTS;
    const stale = method !== "GET" && this.now() - this.usedAt >= STALE_MS;
    if (this.channel === null || this.channel.ended !== null || spent || stale) await this.reopen(headers?.[SECRET_HEADER] ?? "");
    try {
      const res = await this.channel.request(method, path, sentHeaders(headers), body ?? "");
      this.usedAt = this.now();
      return res;
    } catch (err) {
      if (this.closed) throw new RelayError("this session to the engine is closed", "CLOSED");
      throw terminal(err) ?? err;
    }
  }

  async reopen(secret) {
    this.channel?.close();
    this.channel = null;
    let channel;
    try {
      channel = await this.connect(secret);
    } catch (err) {
      throw openFailure(err);
    }
    // The person compared the fingerprint this page showed: a session to
    // another key is never used under it.
    if (channel.engineId !== this.engine.engineId) {
      channel.close();
      throw new RelayError("the engine answered with another key", "UNAVAILABLE", 0, { personMessage: ENGINE_CHANGED });
    }
    if (this.closed) {
      channel.close();
      throw new RelayError("this session to the engine is closed", "CLOSED");
    }
    this.channel = channel;
    this.usedAt = this.now();
  }

  // hide ends the channel when the page is hidden: no session outlives the
  // page being shown. A page restored from the back-forward cache opens a
  // new one with its next request.
  hide() {
    this.channel?.close();
  }

  close() {
    this.closed = true;
    this.channel?.close();
  }
}

// onPageHide runs fn when the page is hidden for good or put in the
// back-forward cache.
function onPageHide(fn) {
  globalThis.window?.addEventListener("pagehide", fn);
}

// relayTransport opens link sessions through the Vault. socket(url) makes
// the WebSocket; open is channel.js's openChannel (a test may wrap it);
// now is the clock for how long a channel has been idle.
export function relayTransport({ socket, open = openChannel, pageHide = onPageHide, now = () => Date.now() }) {
  const connect = (secret) => open((tokenText) => socket(linkSocketURL(tokenText)), { transport: RELAY, secret });
  return {
    kind: RELAY,
    async open(link) {
      let channel;
      try {
        channel = await connect(link.secret);
      } catch (err) {
        throw openFailure(err);
      }
      const session = new RelaySession(channel, connect, now);
      pageHide(() => session.hide());
      return session;
    },
  };
}
