import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const lock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
assert.equal(Object.keys(packageJson.dependencies ?? {}).length, 0, "runtime dependencies must remain zero");
assert.equal(Object.keys(lock.packages?.[""]?.dependencies ?? {}).length, 0, "lockfile gained runtime dependencies");
assert.equal(packageJson.private, true, "staging package must stay private until the publish gate");
assert.equal(packageJson.engines?.node, ">=22");

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const { stdout } = await execFileAsync(npm, ["pack", "--dry-run", "--json", "--ignore-scripts"], {
  encoding: "utf8",
  maxBuffer: 2 * 1024 * 1024,
});
const report = JSON.parse(stdout)[0];
const files = new Set(report.files.map((entry) => entry.path));
for (const required of [
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "docs/CLAIMS_AND_LIMITATIONS.md",
  "docs/ORIGIN.md",
  "docs/THREAT_MODEL.md",
  "dist/index.js",
  "dist/index.d.ts",
  "dist/cli.js",
  "schema/browser-action-receipt.v1.schema.json",
]) {
  assert(files.has(required), `tarball is missing ${required}`);
}
for (const path of files) {
  assert(!/^(test|example|\.github)\//.test(path), `tarball leaked development path ${path}`);
  assert(!/(^|\/)(\.env|.*\.pem|.*\.key)$/.test(path), `tarball leaked sensitive path ${path}`);
}
process.stdout.write(`package-ok files=${files.size} bytes=${report.size}\n`);
