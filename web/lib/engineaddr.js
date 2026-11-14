// The engine address grammar (CONTRACT.md, Direct transport): the https
// origin a person's tunnel publishes for their engine. laptop init and
// record_engine in Postgres (internal/engineaddr) apply the same grammar,
// and so do the portal's pin page and its edge function, which builds the
// per-person connect-src from it. Every checker refuses rather than
// repairs; internal/engineaddr/testdata/addresses.json holds the cases all
// of them run.

// HOST_PORT is what a pattern can state: LDH labels of 1 to 63 characters,
// two or more, the last starting with a letter, then an optional decimal
// port with no leading zero. No lookahead, so Go, Postgres and JavaScript
// read it alike.
const HOST_PORT = /^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?$/;

const MAX_HOST = 253;
const MAX_PORT = 65535;
const HTTPS_PORT = 443;
const SCHEME = "https://";

// Names the portal never calls: the person's own machine, their local
// network, and Basalt's own hosts.
const REFUSED_SUFFIXES = ["localhost", "local", "internal", "home.arpa", "basaltvault.app"];

// parseEngineAddress returns the written form of raw (the origin with no
// trailing slash), or null when raw breaks the grammar. A trailing "/" is
// the only thing it drops.
export function parseEngineAddress(raw) {
  if (typeof raw !== "string" || !raw.startsWith(SCHEME)) return null;
  let rest = raw.slice(SCHEME.length);
  if (rest.endsWith("/")) rest = rest.slice(0, -1);
  const m = HOST_PORT.exec(rest);
  if (m === null) return null;
  const host = m[1];
  if (host.length > MAX_HOST) return null;
  if (REFUSED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) return null;
  if (m[2] !== undefined) {
    const port = Number(m[2]);
    if (port > MAX_PORT || port === HTTPS_PORT) return null;
  }
  return SCHEME + rest;
}

// socketOrigin is the socket (wss) origin of a written engine address:
// wss://<host>[:<port>].
export function socketOrigin(address) {
  return `wss://${address.slice(SCHEME.length)}`;
}
