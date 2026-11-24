// A small stdio JSON-RPC client for `basalt mcp`: initialize, then tools/call.
// A tool result with isError set is returned, never thrown: the held write
// and the other refusals the test checks are error results.
import { spawn } from "node:child_process";
import readline from "node:readline";

const CALL_TIMEOUT_MS = 150000;

export class McpClient {
  #child;
  #next = 1;
  #pending = new Map();
  #stderr = "";

  constructor(bin, args, env) {
    this.#child = spawn(bin, ["mcp", ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
    this.#child.stderr.on("data", (d) => {
      this.#stderr += d.toString();
    });
    this.#child.on("exit", (code) => {
      for (const { reject } of this.#pending.values()) reject(new Error(`basalt mcp exited (${code}): ${this.#stderr.slice(-2000)}`));
      this.#pending.clear();
    });
    readline.createInterface({ input: this.#child.stdout }).on("line", (line) => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        return;
      }
      const waiter = this.#pending.get(msg.id);
      if (!waiter) return;
      this.#pending.delete(msg.id);
      if (msg.error) waiter.reject(new Error(`rpc error ${JSON.stringify(msg.error)}`));
      else waiter.resolve(msg.result);
    });
  }

  get stderr() {
    return this.#stderr;
  }

  #send(obj) {
    this.#child.stdin.write(JSON.stringify(obj) + "\n");
  }

  #request(method, params) {
    const id = this.#next++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, CALL_TIMEOUT_MS);
      this.#pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.#send({ jsonrpc: "2.0", id, method, params });
    });
  }

  async initialize() {
    const result = await this.#request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "basalt-release-e2e", version: "1" },
    });
    this.#send({ jsonrpc: "2.0", method: "notifications/initialized" });
    return result;
  }

  // call returns { isError, data, text }: data is the tool's structured
  // result, or the JSON in its first text block.
  async call(name, args = {}) {
    const result = await this.#request("tools/call", { name, arguments: args });
    const text = (result.content ?? []).map((c) => c.text ?? "").join("\n");
    let data = result.structuredContent;
    if (data === undefined) {
      try {
        data = JSON.parse(text);
      } catch {
        data = {};
      }
    }
    return { isError: result.isError === true, data, text };
  }

  close() {
    this.#child.stdin.end();
    this.#child.kill();
  }
}

// find returns the first value of key anywhere in obj, depth first.
export function find(obj, key) {
  if (obj === null || typeof obj !== "object") return undefined;
  if (Object.hasOwn(obj, key)) return obj[key];
  for (const v of Object.values(obj)) {
    const got = find(v, key);
    if (got !== undefined) return got;
  }
  return undefined;
}
