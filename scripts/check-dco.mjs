import { execFileSync } from "node:child_process";

const base = process.argv[2];
if (!base) {
  process.stderr.write("usage: npm run dco:check -- <base-ref>\n");
  process.exit(2);
}

let commits;
try {
  commits = execFileSync("git", ["rev-list", `${base}..HEAD`], { encoding: "utf8" })
    .trim()
    .split("\n")
    .filter(Boolean);
} catch {
  process.stderr.write(`dco-check: cannot resolve ${base}..HEAD\n`);
  process.exit(2);
}

const signoff = /^Signed-off-by:\s+.+\s+<[^<>\s]+@[^<>\s]+>\s*$/im;
const unsigned = commits.filter((commit) => {
  const message = execFileSync("git", ["show", "-s", "--format=%B", commit], { encoding: "utf8" });
  return !signoff.test(message);
});

if (unsigned.length > 0) {
  process.stderr.write(`dco-check: unsigned commits: ${unsigned.join(", ")}\n`);
  process.exit(1);
}
process.stdout.write(`dco-ok commits=${commits.length}\n`);
