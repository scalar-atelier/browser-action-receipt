import { constants } from "node:fs";
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rm,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import type { BrowserActionReceiptV1, ReceiptSeedV1 } from "./contract.js";
import {
  ContractError,
  assertOperationId,
  canonicalJson,
  isoNow,
} from "./canonical.js";
import {
  assertReceiptSeed,
  buildReceipt,
  parseReceipt,
  type ReceiptResultInput,
} from "./receipt.js";
import type {
  ClaimHandle,
  ClaimOutcome,
  ReceiptLedger,
} from "./ledger-contract.js";

export type { ClaimHandle, ClaimOutcome, ReceiptLedger } from "./ledger-contract.js";

const MAX_LEDGER_FILE_BYTES = 64 * 1024;

interface ClaimHandleState {
  readonly ledger: FileReceiptLedger;
  readonly seed: ReceiptSeedV1;
}

const claimHandles = new WeakMap<ClaimHandle, ClaimHandleState>();

function ioCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

async function assertSafeDirectory(path: string, create: boolean): Promise<void> {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw new ContractError("ledger_path_unsafe", `${path} is not a real directory`);
    }
  } catch (error) {
    if (ioCode(error) !== "ENOENT" || !create) throw error;
    const parent = dirname(path);
    const parentInfo = await lstat(parent);
    if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) {
      throw new ContractError("ledger_path_unsafe", "Ledger parent must be a real directory");
    }
    try {
      await mkdir(path, { mode: 0o700 });
    } catch (mkdirError) {
      if (ioCode(mkdirError) !== "EEXIST") throw mkdirError;
    }
    const created = await lstat(path);
    if (created.isSymbolicLink() || !created.isDirectory()) {
      throw new ContractError("ledger_path_unsafe", `${path} is not a real directory`);
    }
  }
}

async function syncDirectory(path: string): Promise<void> {
  try {
    const handle = await open(path, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (!["EINVAL", "EISDIR", "EPERM", "ENOTSUP"].includes(ioCode(error) ?? "")) throw error;
  }
}

async function writeExclusive(path: string, contents: string): Promise<boolean> {
  const flags = constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0);
  let handle;
  try {
    handle = await open(path, flags, 0o600);
  } catch (error) {
    if (ioCode(error) === "EEXIST") return false;
    throw error;
  }
  try {
    await handle.writeFile(contents, { encoding: "utf8" });
    await handle.sync();
  } finally {
    await handle.close();
  }
  await syncDirectory(dirname(path));
  return true;
}

async function publishExclusive(
  temporaryDirectory: string,
  finalPath: string,
  contents: string,
): Promise<boolean> {
  const temporaryPath = join(temporaryDirectory, `${randomUUID()}.json`);
  if (!(await writeExclusive(temporaryPath, contents))) {
    throw new ContractError("temporary_collision", "Could not allocate a temporary ledger file");
  }
  try {
    try {
      await link(temporaryPath, finalPath);
    } catch (error) {
      if (ioCode(error) === "EEXIST") return false;
      throw error;
    }
    await syncDirectory(dirname(finalPath));
    return true;
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

async function readSmallFile(path: string): Promise<string> {
  const info = await lstat(path);
  if (info.isSymbolicLink() || !info.isFile() || info.size > MAX_LEDGER_FILE_BYTES) {
    throw new ContractError("ledger_file_unsafe", "Ledger file is unsafe or oversized");
  }
  return readFile(path, "utf8");
}

export class FileReceiptLedger implements ReceiptLedger {
  readonly root: string;
  readonly claimsDirectory: string;
  readonly receiptsDirectory: string;
  readonly temporaryDirectory: string;

  constructor(root: string) {
    this.root = resolve(root);
    this.claimsDirectory = join(this.root, "claims");
    this.receiptsDirectory = join(this.root, "receipts");
    this.temporaryDirectory = join(this.root, "tmp");
  }

  async initialize(): Promise<void> {
    await assertSafeDirectory(this.root, true);
    for (const directory of [this.claimsDirectory, this.receiptsDirectory, this.temporaryDirectory]) {
      await assertSafeDirectory(directory, true);
    }
  }

  async claim(seed: ReceiptSeedV1): Promise<ClaimOutcome> {
    assertReceiptSeed(seed);
    await this.initialize();
    const claimed = await publishExclusive(
      this.temporaryDirectory,
      this.claimPath(seed.operationId),
      `${canonicalJson(seed)}\n`,
    );
    if (claimed) {
      const handle = Object.freeze({ operationId: seed.operationId });
      claimHandles.set(handle, { ledger: this, seed });
      return { kind: "claimed", handle };
    }

    const persisted = this.parseClaim(await readSmallFile(this.claimPath(seed.operationId)));
    if (canonicalJson(claimIdentity(persisted)) !== canonicalJson(claimIdentity(seed))) {
      return { kind: "operation_conflict", operationId: seed.operationId };
    }
    const receipt = await this.readReceipt(seed.operationId);
    return receipt === null
      ? { kind: "duplicate_in_progress", operationId: seed.operationId }
      : { kind: "duplicate_final", receipt };
  }

  async readReceipt(operationId: string): Promise<BrowserActionReceiptV1 | null> {
    assertOperationId(operationId);
    await this.initialize();
    try {
      return parseReceipt(await readSmallFile(this.receiptPath(operationId)));
    } catch (error) {
      if (ioCode(error) === "ENOENT") return null;
      throw error;
    }
  }

  async finalize(
    handle: ClaimHandle,
    result: ReceiptResultInput,
    finalizedAt = isoNow(),
  ): Promise<BrowserActionReceiptV1> {
    const state = claimHandles.get(handle);
    if (state === undefined || state.ledger !== this) {
      throw new ContractError("claim_handle_invalid", "Finalization requires this ledger's claim handle");
    }
    return this.finalizeSeed(state.seed, result, finalizedAt);
  }

  private async finalizeSeed(
    seed: ReceiptSeedV1,
    result: ReceiptResultInput,
    finalizedAt: string,
  ): Promise<BrowserActionReceiptV1> {
    assertReceiptSeed(seed);
    await this.initialize();
    let persisted: ReceiptSeedV1;
    try {
      persisted = this.parseClaim(await readSmallFile(this.claimPath(seed.operationId)));
    } catch (error) {
      if (ioCode(error) === "ENOENT") {
        throw new ContractError("claim_missing", "A safe claim is required before finalization");
      }
      throw error;
    }
    if (canonicalJson(persisted) !== canonicalJson(seed)) {
      throw new ContractError("claim_conflict", "Finalization seed does not match the persisted claim");
    }
    const existing = await this.readReceipt(seed.operationId);
    if (existing !== null) return existing;

    const receipt = buildReceipt(seed, result, finalizedAt);
    const published = await publishExclusive(
      this.temporaryDirectory,
      this.receiptPath(seed.operationId),
      `${canonicalJson(receipt)}\n`,
    );
    if (!published) {
      const raced = await this.readReceipt(seed.operationId);
      if (raced !== null) return raced;
      throw new ContractError("receipt_race_invalid", "Receipt path exists without a readable receipt");
    }
    return receipt;
  }

  async recoverUnknownClaims(before: Date): Promise<BrowserActionReceiptV1[]> {
    if (!Number.isFinite(before.getTime())) {
      throw new ContractError("timestamp_invalid", "Recovery cutoff is invalid");
    }
    await this.initialize();
    const recovered: BrowserActionReceiptV1[] = [];
    for (const name of (await readdir(this.claimsDirectory)).sort()) {
      const match = /^([0-9a-f-]{36})\.json$/.exec(name);
      if (match?.[1] === undefined) continue;
      const operationId = match[1];
      assertOperationId(operationId);
      if ((await this.readReceipt(operationId)) !== null) continue;
      const seed = this.parseClaim(await readSmallFile(this.claimPath(operationId)));
      if (seed.claimedAt >= before.toISOString()) continue;
      recovered.push(
        await this.finalizeSeed(
          seed,
          {
            status: "unknown_after_claim",
            errorCode: "unknown_after_claim",
          },
          isoNow(),
        ),
      );
    }
    return recovered;
  }

  private claimPath(operationId: string): string {
    assertOperationId(operationId);
    return join(this.claimsDirectory, `${operationId}.json`);
  }

  private receiptPath(operationId: string): string {
    assertOperationId(operationId);
    return join(this.receiptsDirectory, `${operationId}.json`);
  }

  private parseClaim(text: string): ReceiptSeedV1 {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new ContractError("claim_json_invalid", "Claim is not valid JSON");
    }
    assertReceiptSeed(value);
    return value;
  }
}

function claimIdentity(seed: ReceiptSeedV1): Omit<ReceiptSeedV1, "claimedAt"> {
  const { claimedAt: _claimedAt, ...identity } = seed;
  return identity;
}
