import { readFile } from "node:fs/promises";
import { FileReceiptLedger } from "../dist/index.js";

const [, , ledgerRoot, seedPath] = process.argv;
if (!ledgerRoot || !seedPath) process.exit(2);
const seed = JSON.parse(await readFile(seedPath, "utf8"));
const outcome = await new FileReceiptLedger(ledgerRoot).claim(seed);
process.stdout.write(outcome.kind);
