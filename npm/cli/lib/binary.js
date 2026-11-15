"use strict";

const path = require("path");

const packages = {
  "linux-x64": "@basaltdb/linux-x64",
  "linux-arm64": "@basaltdb/linux-arm64",
  "darwin-x64": "@basaltdb/darwin-x64",
  "darwin-arm64": "@basaltdb/darwin-arm64",
};

function platformKey() {
  const plat = process.platform;
  const arch = process.arch;
  return plat + "-" + arch;
}

function resolveBinary(name) {
  const key = platformKey();
  const pkg = packages[key];
  if (!pkg) {
    throw new Error(
      "BasaltDB has no npm binary for " +
        key +
        ". Windows is not supported yet; use WSL. On other systems use install.sh or a release archive.",
    );
  }
  try {
    return require.resolve(path.join(pkg, "bin", name));
  } catch {
    throw new Error(
      "optionalDependency " +
        pkg +
        " is not installed. Install @basaltdb/cli with npm, pnpm or yarn (optional deps must be enabled).",
    );
  }
}

function spawnBinary(name, argv) {
  const { spawn } = require("child_process");
  const child = spawn(resolveBinary(name), argv, { stdio: "inherit" });
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

module.exports = { platformKey, resolveBinary, spawnBinary, packages };
