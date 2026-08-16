#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { ContractError } from "./canonical.js";
import { FileReceiptLedger } from "./ledger.js";
import { parseReceipt } from "./receipt.js";

async function main(): Promise<number> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      before: { type: "string" },
    },
  });
  const command = positionals[0];
  if (command === "verify" && positionals[1] !== undefined) {
    const receipt = parseReceipt(await readFile(resolve(positionals[1]), "utf8"));
    process.stdout.write(`valid ${receipt.operationId} ${receipt.result.status}\n`);
    return 0;
  }
  if (command === "recover" && positionals[1] !== undefined && values.before !== undefined) {
    const before = new Date(values.before);
    const recovered = await new FileReceiptLedger(resolve(positionals[1])).recoverUnknownClaims(before);
    process.stdout.write(`recovered ${recovered.length}\n`);
    return 0;
  }
  process.stderr.write(
    "usage:\n  browser-action-receipt verify <receipt.json>\n" +
      "  browser-action-receipt recover <ledger-directory> --before <ISO timestamp>\n",
  );
  return 2;
}

try {
  process.exitCode = await main();
} catch (error) {
  const code = error instanceof ContractError ? error.code : "unexpected_error";
  process.stderr.write(`invalid ${code}\n`);
  process.exitCode = 1;
}
