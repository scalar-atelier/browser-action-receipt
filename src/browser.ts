import {
  ACTIONS,
  RISK_CLASSES,
  type ApprovalDecisionV1,
  type ApprovalRequestV1,
  type AtomicActionAdapter,
  type AtomicActionResult,
  type BrowserAction,
  type BrowserActionReceiptV1,
  type CaptureEvidence,
  type ExecutionOutcome,
  type JsonValue,
  type PreparedActionHandle,
  type ReceiptSeedV1,
  type RiskClass,
  type TargetObservationV1,
} from "./contract.js";
import {
  ContractError,
  assertExactKeys,
  assertIsoTimestamp,
  assertOperationId,
  assertSafeArtifactRef,
  assertSha256,
  canonicalJson,
  cloneFrozenJson,
  isoNow,
} from "./canonical.js";

export {
  ACTIONS,
  RISK_CLASSES,
  ContractError,
  canonicalJson,
};
export type {
  ApprovalDecisionV1,
  ApprovalRequestV1,
  AtomicActionAdapter,
  AtomicActionInput,
  AtomicActionResult,
  BrowserAction,
  BrowserActionReceiptV1,
  CaptureEvidence,
  CaptureEvidenceV1,
  ExecutionOutcome,
  JsonValue,
  PreparedActionHandle,
  RiskClass,
  TargetObservationV1,
} from "./contract.js";

const ACTION_SET = new Set<string>(ACTIONS);
const RISK_SET = new Set<string>(RISK_CLASSES);
const MAX_FINGERPRINT_BYTES = 64 * 1024;
const MAX_APPROVAL_TTL_MS = 10 * 60 * 1000;
const DECISIONS = new Set(["approved", "denied", "expired", "invalid"]);
const STATUSES = new Set([
  "committed",
  "blocked",
  "aborted_target_changed",
  "unknown_after_claim",
  "unknown_after_adapter",
]);
const EVIDENCE_STATUSES = new Set(["captured", "not_requested", "capture_failed"]);
const STATUS_ERROR_CODES: Readonly<Record<string, ReadonlySet<string>>> = Object.freeze({
  blocked: new Set(["approval_required", "approval_invalid", "approval_expired", "approval_denied", "clock_invalid"]),
  aborted_target_changed: new Set(["target_changed"]),
  unknown_after_claim: new Set(["unknown_after_claim"]),
  unknown_after_adapter: new Set(["adapter_threw", "adapter_contract_violation"]),
});

interface PreparedInternal {
  readonly action: BrowserAction;
  readonly riskClass: RiskClass;
  readonly operationId: string;
  readonly observation: TargetObservationV1;
  readonly payload: JsonValue;
  readonly bindingSha256: string;
  readonly preparedAt: string;
  readonly expiresAt: string;
}

export interface CreateObservationInput {
  readonly url: string;
  readonly targetFingerprint: string;
  readonly pageGeneration: string;
  readonly observedAt?: string;
}

export interface PrepareActionInput {
  readonly action: BrowserAction;
  readonly riskClass: RiskClass;
  readonly observation: TargetObservationV1;
  readonly payload: unknown;
  readonly approvalDisplay: {
    readonly title: string;
    readonly detail: string;
  };
  readonly operationId?: string;
  readonly approvalTtlMs?: number;
  readonly now?: Date;
}

export interface ReceiptResultInput {
  readonly status: BrowserActionReceiptV1["result"]["status"];
  readonly errorCode: string | null;
  readonly artifactRefSha256?: string | null;
  readonly contentHash?: string | null;
  readonly evidenceStatus?: BrowserActionReceiptV1["result"]["evidenceStatus"];
  readonly evidenceErrorCode?: string | null;
}

export interface BrowserClaimHandle {
  readonly operationId: string;
}

export type BrowserStoreClaimOutcome =
  | { readonly kind: "claimed" }
  | { readonly kind: "duplicate_final"; readonly receipt: unknown }
  | { readonly kind: "duplicate_in_progress"; readonly operationId: string }
  | { readonly kind: "operation_conflict"; readonly operationId: string };

export type BrowserStorePublishOutcome =
  | { readonly kind: "stored" }
  | { readonly kind: "duplicate_final"; readonly receipt: unknown };

/**
 * Persistence-only boundary. The package creates and verifies claims/receipts;
 * a host such as Tauri only performs atomic storage operations.
 */
export interface BrowserReceiptStore {
  claim(seed: ReceiptSeedV1): Promise<BrowserStoreClaimOutcome>;
  publish(receipt: BrowserActionReceiptV1): Promise<BrowserStorePublishOutcome>;
  listOpenClaims?(before: string): Promise<readonly unknown[]>;
}

export type BrowserClaimOutcome =
  | { readonly kind: "claimed"; readonly handle: BrowserClaimHandle }
  | { readonly kind: "duplicate_final"; readonly receipt: BrowserActionReceiptV1 }
  | { readonly kind: "duplicate_in_progress"; readonly operationId: string }
  | { readonly kind: "operation_conflict"; readonly operationId: string };

export interface BrowserReceiptLedgerLike {
  claim(seed: ReceiptSeedV1): Promise<BrowserClaimOutcome>;
  finalize(
    handle: BrowserClaimHandle,
    result: ReceiptResultInput,
    finalizedAt?: string,
  ): Promise<BrowserActionReceiptV1>;
}

export interface ExecutePreparedActionInput {
  readonly prepared: PreparedActionHandle;
  readonly decision?: ApprovalDecisionV1;
  readonly adapter: AtomicActionAdapter;
  readonly ledger: BrowserReceiptLedgerLike;
  readonly capture?: CaptureEvidence;
  readonly now?: Date;
}

interface ApprovalEvaluation {
  readonly projection: BrowserActionReceiptV1["approval"];
  readonly blockCode: string | null;
}

const preparedActions = new WeakMap<PreparedActionHandle, PreparedInternal>();
const browserClaimHandles = new WeakMap<BrowserClaimHandle, { ledger: BrowserReceiptLedger; seed: ReceiptSeedV1 }>();

function webCrypto(): Crypto {
  const value = globalThis.crypto;
  if (value?.subtle === undefined || typeof value.getRandomValues !== "function") {
    throw new ContractError("web_crypto_unavailable", "Web Crypto is required");
  }
  return value;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const source = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const bytes = new Uint8Array(source.byteLength);
  bytes.set(source);
  return bytesToHex(new Uint8Array(await webCrypto().subtle.digest("SHA-256", bytes.buffer)));
}

function equalSha256(left: string, right: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(left) || !/^[0-9a-f]{64}$/.test(right)) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

function randomOperationId(): string {
  const crypto = webCrypto();
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function randomNonce(): string {
  return bytesToHex(webCrypto().getRandomValues(new Uint8Array(32)));
}

function assertString(value: unknown, field: string, max = 512): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) {
    throw new ContractError("field_invalid", `${field} must be a non-empty string`);
  }
}

function approvalDisplay(value: PrepareActionInput["approvalDisplay"]): ApprovalRequestV1["display"] {
  if (value === null || typeof value !== "object") {
    throw new ContractError("approval_display_invalid", "approvalDisplay is required");
  }
  const normalize = (text: unknown, field: string, max: number): string => {
    if (
      typeof text !== "string" ||
      text.length < 1 ||
      text.length > max ||
      /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(text) ||
      text !== text.normalize("NFC") ||
      text !== text.trim()
    ) {
      throw new ContractError("approval_display_invalid", `${field} is invalid`);
    }
    return text;
  };
  return Object.freeze({
    title: normalize(value.title, "approvalDisplay.title", 160),
    detail: normalize(value.detail, "approvalDisplay.detail", 500),
  });
}

function assertTargetObservation(value: unknown): asserts value is TargetObservationV1 {
  assertExactKeys(
    value,
    ["schemaVersion", "origin", "pathnameSha256", "targetFingerprintSha256", "pageGeneration", "observedAt"],
    "targetObservation",
  );
  if (value.schemaVersion !== "browser-target-observation/v1") {
    throw new ContractError("schema_version_invalid", "Unknown target observation schema");
  }
  assertString(value.origin, "origin", 512);
  let parsed: URL;
  try {
    parsed = new URL(value.origin);
  } catch {
    throw new ContractError("origin_invalid", "origin must be a URL origin");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.origin !== value.origin ||
    parsed.username !== "" ||
    parsed.password !== ""
  ) {
    throw new ContractError("origin_invalid", "origin must be a canonical HTTP(S) origin");
  }
  assertSha256(value.pathnameSha256, "pathnameSha256");
  assertSha256(value.targetFingerprintSha256, "targetFingerprintSha256");
  assertString(value.pageGeneration, "pageGeneration", 256);
  assertIsoTimestamp(value.observedAt, "observedAt");
}

function assertApprovalRequest(value: unknown): asserts value is ApprovalRequestV1 {
  assertExactKeys(
    value,
    ["schemaVersion", "operationId", "action", "riskClass", "origin", "display", "bindingSha256", "expiresAt"],
    "approvalRequest",
  );
  if (value.schemaVersion !== "browser-approval-request/v1") {
    throw new ContractError("approval_invalid", "Unknown approval request schema");
  }
  assertOperationId(value.operationId);
  if (typeof value.action !== "string" || !ACTION_SET.has(value.action)) {
    throw new ContractError("approval_invalid", "Approval request action is invalid");
  }
  if (typeof value.riskClass !== "string" || !RISK_SET.has(value.riskClass)) {
    throw new ContractError("approval_invalid", "Approval request risk is invalid");
  }
  if (typeof value.origin !== "string") throw new ContractError("approval_invalid", "Approval origin is invalid");
  assertExactKeys(value.display, ["title", "detail"], "approvalRequest.display");
  approvalDisplay(value.display as PrepareActionInput["approvalDisplay"]);
  assertSha256(value.bindingSha256, "bindingSha256");
  assertIsoTimestamp(value.expiresAt, "expiresAt");
}

function assertApproval(value: unknown): asserts value is BrowserActionReceiptV1["approval"] {
  assertExactKeys(value, ["decision", "channel", "decidedAt", "bindingSha256"], "approval");
  if (typeof value.decision !== "string" || !DECISIONS.has(value.decision)) {
    throw new ContractError("approval_invalid", "Unknown approval decision");
  }
  if (value.channel !== null && value.channel !== "host" && value.channel !== "native") {
    throw new ContractError("approval_invalid", "Unknown approval channel");
  }
  if (value.decidedAt !== null) assertIsoTimestamp(value.decidedAt, "decidedAt");
  assertSha256(value.bindingSha256, "bindingSha256");
  if (value.decision === "invalid") {
    if (value.channel !== null || value.decidedAt !== null) {
      throw new ContractError("approval_invalid", "Non-decisions cannot have a channel or decision time");
    }
  } else if (value.channel === null || value.decidedAt === null) {
    throw new ContractError("approval_invalid", "A decision requires a channel and decision time");
  }
}

function assertReceiptTarget(value: unknown): asserts value is BrowserActionReceiptV1["target"] {
  assertExactKeys(value, ["origin", "pathnameSha256", "fingerprintSha256", "pageGenerationSha256"], "target");
  assertString(value.origin, "target.origin", 512);
  let parsed: URL;
  try {
    parsed = new URL(value.origin);
  } catch {
    throw new ContractError("origin_invalid", "target.origin must be a URL origin");
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== value.origin) {
    throw new ContractError("origin_invalid", "target.origin must be canonical HTTP(S)");
  }
  assertSha256(value.pathnameSha256, "target.pathnameSha256");
  assertSha256(value.fingerprintSha256, "target.fingerprintSha256");
  assertSha256(value.pageGenerationSha256, "target.pageGenerationSha256");
}

function normalizedResult(input: ReceiptResultInput): BrowserActionReceiptV1["result"] {
  const result: BrowserActionReceiptV1["result"] = {
    status: input.status,
    errorCode: input.errorCode,
    artifactRefSha256: input.artifactRefSha256 ?? null,
    contentHash: input.contentHash ?? null,
    evidenceStatus: input.evidenceStatus ?? "not_requested",
    evidenceErrorCode: input.evidenceErrorCode ?? null,
  };
  assertResult(result);
  return result;
}

function assertResult(value: unknown): asserts value is BrowserActionReceiptV1["result"] {
  assertExactKeys(
    value,
    ["status", "errorCode", "artifactRefSha256", "contentHash", "evidenceStatus", "evidenceErrorCode"],
    "result",
  );
  if (typeof value.status !== "string" || !STATUSES.has(value.status)) {
    throw new ContractError("result_invalid", "Unknown result status");
  }
  if (value.errorCode !== null && typeof value.errorCode !== "string") {
    throw new ContractError("error_code_invalid", "errorCode is invalid");
  }
  if (value.artifactRefSha256 !== null) assertSha256(value.artifactRefSha256, "artifactRefSha256");
  if (value.contentHash !== null) assertSha256(value.contentHash, "contentHash");
  if (typeof value.evidenceStatus !== "string" || !EVIDENCE_STATUSES.has(value.evidenceStatus)) {
    throw new ContractError("result_invalid", "Unknown evidence status");
  }
  if (value.evidenceErrorCode !== null && value.evidenceErrorCode !== "capture_failed") {
    throw new ContractError("error_code_invalid", "evidenceErrorCode is invalid");
  }
  if (value.status === "committed" && value.errorCode !== null) {
    throw new ContractError("result_invalid", "Committed actions cannot have an action error");
  }
  if (value.status !== "committed" && value.errorCode === null) {
    throw new ContractError("result_invalid", "Non-committed actions require an error code");
  }
  if (value.status !== "committed" && !STATUS_ERROR_CODES[value.status]?.has(value.errorCode as string)) {
    throw new ContractError("result_invalid", "Result error code does not match its status");
  }
  if (value.evidenceStatus === "captured") {
    if (value.artifactRefSha256 === null || value.contentHash === null || value.evidenceErrorCode !== null) {
      throw new ContractError("result_invalid", "Captured evidence is incomplete");
    }
  } else if (value.artifactRefSha256 !== null || value.contentHash !== null) {
    throw new ContractError("result_invalid", "Evidence fields must be null when not captured");
  }
  if ((value.evidenceStatus === "capture_failed") !== (value.evidenceErrorCode !== null)) {
    throw new ContractError("result_invalid", "Evidence error does not match evidence status");
  }
}

function assertReceiptSeed(value: unknown): asserts value is ReceiptSeedV1 {
  assertExactKeys(
    value,
    ["schemaVersion", "operationId", "action", "riskClass", "approval", "target", "preparedAt", "claimedAt"],
    "claim",
  );
  if (value.schemaVersion !== "browser-action-claim/v1") {
    throw new ContractError("schema_version_invalid", "Unknown claim schema");
  }
  assertOperationId(value.operationId);
  if (typeof value.action !== "string" || !ACTION_SET.has(value.action)) {
    throw new ContractError("action_invalid", "Unknown browser action");
  }
  if (typeof value.riskClass !== "string" || !RISK_SET.has(value.riskClass)) {
    throw new ContractError("risk_invalid", "Unknown risk class");
  }
  assertApproval(value.approval);
  assertReceiptTarget(value.target);
  assertIsoTimestamp(value.preparedAt, "preparedAt");
  assertIsoTimestamp(value.claimedAt, "claimedAt");
  if (value.claimedAt < value.preparedAt) {
    throw new ContractError("timestamp_invalid", "claimedAt precedes preparedAt");
  }
}

function assertReceiptShape(value: unknown): asserts value is BrowserActionReceiptV1 {
  assertExactKeys(
    value,
    ["schemaVersion", "operationId", "action", "riskClass", "approval", "target", "result", "preparedAt", "finalizedAt", "receiptSha256"],
    "receipt",
  );
  if (value.schemaVersion !== "browser-action-receipt/v1") {
    throw new ContractError("schema_version_invalid", "Unknown receipt schema");
  }
  assertOperationId(value.operationId);
  if (typeof value.action !== "string" || !ACTION_SET.has(value.action)) {
    throw new ContractError("action_invalid", "Unknown browser action");
  }
  if (typeof value.riskClass !== "string" || !RISK_SET.has(value.riskClass)) {
    throw new ContractError("risk_invalid", "Unknown risk class");
  }
  assertApproval(value.approval);
  assertReceiptTarget(value.target);
  assertResult(value.result);
  assertIsoTimestamp(value.preparedAt, "preparedAt");
  assertIsoTimestamp(value.finalizedAt, "finalizedAt");
  if (value.finalizedAt < value.preparedAt) {
    throw new ContractError("timestamp_invalid", "finalizedAt precedes preparedAt");
  }
  if (
    value.approval.decidedAt !== null &&
    (value.approval.decidedAt < value.preparedAt || value.approval.decidedAt > value.finalizedAt)
  ) {
    throw new ContractError("timestamp_invalid", "Approval time is outside the receipt interval");
  }
  if (
    ["committed", "aborted_target_changed", "unknown_after_adapter"].includes(value.result.status) &&
    value.approval.decision !== "approved"
  ) {
    throw new ContractError("receipt_semantics_invalid", "Adapter outcomes require an approved decision");
  }
  if (value.result.status === "blocked" && value.approval.decision === "approved") {
    throw new ContractError("receipt_semantics_invalid", "An approved action cannot have a blocked result");
  }
  if (value.result.evidenceStatus !== "not_requested" && value.result.status !== "committed") {
    throw new ContractError("receipt_semantics_invalid", "Evidence capture requires a committed action");
  }
  assertSha256(value.receiptSha256, "receiptSha256");
}

export async function verifyReceipt(value: unknown): Promise<BrowserActionReceiptV1> {
  assertReceiptShape(value);
  const { receiptSha256, ...withoutHash } = value;
  if (!equalSha256(receiptSha256, await sha256Hex(canonicalJson(withoutHash)))) {
    throw new ContractError("receipt_hash_mismatch", "Receipt hash does not match its contents");
  }
  return value;
}

export async function parseReceipt(text: string): Promise<BrowserActionReceiptV1> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ContractError("receipt_json_invalid", "Receipt is not valid JSON");
  }
  return verifyReceipt(value);
}

async function receiptTarget(observation: TargetObservationV1): Promise<BrowserActionReceiptV1["target"]> {
  assertTargetObservation(observation);
  return Object.freeze({
    origin: observation.origin,
    pathnameSha256: observation.pathnameSha256,
    fingerprintSha256: observation.targetFingerprintSha256,
    pageGenerationSha256: await sha256Hex(observation.pageGeneration),
  });
}

function observationsMatch(left: TargetObservationV1, right: TargetObservationV1): boolean {
  assertTargetObservation(left);
  assertTargetObservation(right);
  return (
    left.origin === right.origin &&
    equalSha256(left.pathnameSha256, right.pathnameSha256) &&
    equalSha256(left.targetFingerprintSha256, right.targetFingerprintSha256) &&
    left.pageGeneration === right.pageGeneration
  );
}

async function buildReceipt(
  seed: ReceiptSeedV1,
  resultInput: ReceiptResultInput,
  finalizedAt: string,
): Promise<BrowserActionReceiptV1> {
  assertReceiptSeed(seed);
  assertIsoTimestamp(finalizedAt, "finalizedAt");
  const withoutHash = {
    schemaVersion: "browser-action-receipt/v1" as const,
    operationId: seed.operationId,
    action: seed.action,
    riskClass: seed.riskClass,
    approval: seed.approval,
    target: seed.target,
    result: normalizedResult(resultInput),
    preparedAt: seed.preparedAt,
    finalizedAt,
  };
  const receipt = Object.freeze({
    ...withoutHash,
    receiptSha256: await sha256Hex(canonicalJson(withoutHash)),
  });
  return verifyReceipt(receipt);
}

export class BrowserReceiptLedger implements BrowserReceiptLedgerLike {
  readonly store: BrowserReceiptStore;

  constructor(store: BrowserReceiptStore) {
    this.store = store;
  }

  async claim(seed: ReceiptSeedV1): Promise<BrowserClaimOutcome> {
    assertReceiptSeed(seed);
    const persistedSeed = cloneFrozenJson(seed) as unknown as ReceiptSeedV1;
    const outcome = await this.store.claim(persistedSeed);
    if (outcome.kind === "claimed") {
      const handle = Object.freeze({ operationId: seed.operationId });
      browserClaimHandles.set(handle, { ledger: this, seed: persistedSeed });
      return { kind: "claimed", handle };
    }
    if (outcome.kind === "duplicate_final") {
      const receipt = await verifyReceipt(outcome.receipt);
      if (receipt.operationId !== seed.operationId) {
        throw new ContractError("ledger_contract_violation", "Duplicate receipt operation does not match");
      }
      return { kind: "duplicate_final", receipt };
    }
    if (outcome.kind === "duplicate_in_progress" || outcome.kind === "operation_conflict") {
      assertOperationId(outcome.operationId);
      if (outcome.operationId !== seed.operationId) {
        throw new ContractError("ledger_contract_violation", "Claim outcome operation does not match");
      }
      return outcome;
    }
    throw new ContractError("ledger_contract_violation", "Unknown claim outcome");
  }

  async finalize(
    handle: BrowserClaimHandle,
    result: ReceiptResultInput,
    finalizedAt = isoNow(),
  ): Promise<BrowserActionReceiptV1> {
    const state = browserClaimHandles.get(handle);
    if (state === undefined || state.ledger !== this) {
      throw new ContractError("claim_handle_invalid", "Finalization requires this ledger's claim handle");
    }
    return this.publishBuilt(await buildReceipt(state.seed, result, finalizedAt));
  }

  async recoverUnknownClaims(before: Date): Promise<BrowserActionReceiptV1[]> {
    if (!Number.isFinite(before.getTime())) {
      throw new ContractError("timestamp_invalid", "Recovery cutoff is invalid");
    }
    if (this.store.listOpenClaims === undefined) return [];
    const recovered: BrowserActionReceiptV1[] = [];
    for (const rawSeed of await this.store.listOpenClaims(before.toISOString())) {
      assertReceiptSeed(rawSeed);
      if (rawSeed.claimedAt >= before.toISOString()) continue;
      recovered.push(await this.publishBuilt(await buildReceipt(rawSeed, {
        status: "unknown_after_claim",
        errorCode: "unknown_after_claim",
      }, isoNow())));
    }
    return recovered;
  }

  private async publishBuilt(receipt: BrowserActionReceiptV1): Promise<BrowserActionReceiptV1> {
    const outcome = await this.store.publish(receipt);
    if (outcome.kind === "stored") return receipt;
    if (outcome.kind === "duplicate_final") {
      const existing = await verifyReceipt(outcome.receipt);
      if (existing.operationId !== receipt.operationId) {
        throw new ContractError("ledger_contract_violation", "Duplicate receipt operation does not match");
      }
      return existing;
    }
    throw new ContractError("ledger_contract_violation", "Unknown publish outcome");
  }
}

export async function createTargetObservation(input: CreateObservationInput): Promise<TargetObservationV1> {
  if (typeof input.targetFingerprint !== "string" || input.targetFingerprint.length === 0) {
    throw new ContractError("fingerprint_invalid", "targetFingerprint must not be empty");
  }
  if (new TextEncoder().encode(input.targetFingerprint).byteLength > MAX_FINGERPRINT_BYTES) {
    throw new ContractError("fingerprint_invalid", "targetFingerprint is too large");
  }
  if (
    typeof input.pageGeneration !== "string" ||
    input.pageGeneration.length === 0 ||
    input.pageGeneration.length > 256
  ) {
    throw new ContractError("page_generation_invalid", "pageGeneration must be 1..256 characters");
  }
  let parsed: URL;
  try {
    parsed = new URL(input.url);
  } catch {
    throw new ContractError("url_invalid", "url must be an absolute URL");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username !== "" || parsed.password !== "") {
    throw new ContractError("url_invalid", "Only credential-free HTTP(S) URLs are accepted");
  }
  const observation: TargetObservationV1 = {
    schemaVersion: "browser-target-observation/v1",
    origin: parsed.origin,
    pathnameSha256: await sha256Hex(parsed.pathname),
    targetFingerprintSha256: await sha256Hex(input.targetFingerprint),
    pageGeneration: input.pageGeneration,
    observedAt: input.observedAt ?? isoNow(),
  };
  assertTargetObservation(observation);
  return Object.freeze(observation);
}

export async function prepareAction(input: PrepareActionInput): Promise<PreparedActionHandle> {
  if (!ACTION_SET.has(input.action)) throw new ContractError("action_invalid", "Unknown browser action");
  if (!RISK_SET.has(input.riskClass)) throw new ContractError("risk_invalid", "Unknown risk class");
  const operationId = input.operationId ?? randomOperationId();
  assertOperationId(operationId);
  const now = input.now ?? new Date();
  const preparedAt = isoNow(now);
  const ttl = input.approvalTtlMs ?? 120_000;
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > MAX_APPROVAL_TTL_MS) {
    throw new ContractError("approval_ttl_invalid", "approvalTtlMs is outside 1..600000");
  }
  assertTargetObservation(input.observation);
  const observation = Object.freeze({ ...input.observation });
  const payload = cloneFrozenJson(input.payload);
  const display = approvalDisplay(input.approvalDisplay);
  const bindingSha256 = await sha256Hex(canonicalJson({
    operationId,
    action: input.action,
    riskClass: input.riskClass,
    observation,
    payload,
    display,
    bindingNonce: randomNonce(),
  }));
  const expiresAt = isoNow(new Date(now.getTime() + ttl));
  const approvalRequest: ApprovalRequestV1 = Object.freeze({
    schemaVersion: "browser-approval-request/v1",
    operationId,
    action: input.action,
    riskClass: input.riskClass,
    origin: observation.origin,
    display,
    bindingSha256,
    expiresAt,
  });
  const handle: PreparedActionHandle = Object.freeze({
    operationId,
    action: input.action,
    riskClass: input.riskClass,
    approvalRequest,
  });
  preparedActions.set(handle, {
    operationId,
    action: input.action,
    riskClass: input.riskClass,
    observation,
    payload,
    bindingSha256,
    preparedAt,
    expiresAt,
  });
  return handle;
}

export function makeApprovalDecision(
  request: ApprovalRequestV1,
  decision: "approved" | "denied",
  options: { readonly channel?: "host" | "native"; readonly now?: Date } = {},
): ApprovalDecisionV1 {
  assertApprovalRequest(request);
  return Object.freeze({
    schemaVersion: "browser-approval-decision/v1",
    operationId: request.operationId,
    bindingSha256: request.bindingSha256,
    decision,
    channel: options.channel ?? "host",
    decidedAt: isoNow(options.now ?? new Date()),
    expiresAt: request.expiresAt,
  });
}

function evaluateApproval(
  prepared: PreparedInternal,
  decision: ApprovalDecisionV1 | undefined,
  now: Date,
): ApprovalEvaluation {
  const currentTime = isoNow(now);
  if (currentTime < prepared.preparedAt) {
    return {
      projection: { decision: "invalid", channel: null, decidedAt: null, bindingSha256: prepared.bindingSha256 },
      blockCode: "clock_invalid",
    };
  }
  if (decision === undefined) {
    return {
      projection: { decision: "invalid", channel: null, decidedAt: null, bindingSha256: prepared.bindingSha256 },
      blockCode: "approval_required",
    };
  }
  try {
    assertExactKeys(
      decision,
      ["schemaVersion", "operationId", "bindingSha256", "decision", "channel", "decidedAt", "expiresAt"],
      "approvalDecision",
    );
    if (decision.schemaVersion !== "browser-approval-decision/v1") throw new Error("schema");
    assertOperationId(decision.operationId);
    assertSha256(decision.bindingSha256, "bindingSha256");
    assertIsoTimestamp(decision.decidedAt, "decidedAt");
    assertIsoTimestamp(decision.expiresAt, "expiresAt");
    if (!["approved", "denied"].includes(decision.decision)) throw new Error("decision");
    if (!["host", "native"].includes(decision.channel)) throw new Error("channel");
    if (
      decision.operationId !== prepared.operationId ||
      !equalSha256(decision.bindingSha256, prepared.bindingSha256) ||
      decision.expiresAt !== prepared.expiresAt ||
      decision.decidedAt < prepared.preparedAt ||
      decision.decidedAt > currentTime ||
      decision.decidedAt > decision.expiresAt
    ) {
      throw new Error("binding");
    }
  } catch {
    return {
      projection: { decision: "invalid", channel: null, decidedAt: null, bindingSha256: prepared.bindingSha256 },
      blockCode: "approval_invalid",
    };
  }
  if (currentTime > prepared.expiresAt) {
    return {
      projection: { decision: "expired", channel: decision.channel, decidedAt: decision.decidedAt, bindingSha256: prepared.bindingSha256 },
      blockCode: "approval_expired",
    };
  }
  if (decision.decision === "denied") {
    return {
      projection: { decision: "denied", channel: decision.channel, decidedAt: decision.decidedAt, bindingSha256: prepared.bindingSha256 },
      blockCode: "approval_denied",
    };
  }
  return {
    projection: { decision: "approved", channel: decision.channel, decidedAt: decision.decidedAt, bindingSha256: prepared.bindingSha256 },
    blockCode: null,
  };
}

function assertAtomicActionResult(value: unknown): asserts value is AtomicActionResult {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ContractError("adapter_contract_violation", "Adapter result must be an object");
  }
  const status = (value as { status?: unknown }).status;
  if (status === "committed" || status === "target_changed") {
    assertExactKeys(value, ["status", "observation"], "adapterResult");
    assertTargetObservation(value.observation);
    return;
  }
  throw new ContractError("adapter_contract_violation", "Adapter status is invalid");
}

export async function executePreparedAction(input: ExecutePreparedActionInput): Promise<ExecutionOutcome> {
  const prepared = preparedActions.get(input.prepared);
  if (prepared === undefined) {
    throw new ContractError("prepared_handle_invalid", "Prepared action was not created by this module instance");
  }
  if (input.adapter.capability !== "atomic-compare-and-act/v1") {
    throw new ContractError("adapter_not_atomic", "Adapter does not declare atomic compare-and-act support");
  }
  const now = input.now ?? new Date();
  const approval = evaluateApproval(prepared, input.decision, now);
  const seed: ReceiptSeedV1 = Object.freeze({
    schemaVersion: "browser-action-claim/v1",
    operationId: prepared.operationId,
    action: prepared.action,
    riskClass: prepared.riskClass,
    approval: approval.projection,
    target: await receiptTarget(prepared.observation),
    preparedAt: prepared.preparedAt,
    claimedAt: isoNow(now < new Date(prepared.preparedAt) ? new Date(prepared.preparedAt) : now),
  });
  const claim = await input.ledger.claim(seed);
  if (claim.kind !== "claimed") return claim;
  if (approval.blockCode !== null) {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "blocked",
      errorCode: approval.blockCode,
    }) };
  }

  let rawActionResult: unknown;
  try {
    rawActionResult = await input.adapter.compareAndAct({
      action: prepared.action,
      payload: prepared.payload,
      expected: prepared.observation,
    });
  } catch {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "unknown_after_adapter",
      errorCode: "adapter_threw",
    }) };
  }
  try {
    assertAtomicActionResult(rawActionResult);
  } catch {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "unknown_after_adapter",
      errorCode: "adapter_contract_violation",
    }) };
  }
  const matches = observationsMatch(prepared.observation, rawActionResult.observation);
  if (rawActionResult.status === "target_changed") {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: matches ? "unknown_after_adapter" : "aborted_target_changed",
      errorCode: matches ? "adapter_contract_violation" : "target_changed",
    }) };
  }
  if (!matches) {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "unknown_after_adapter",
      errorCode: "adapter_contract_violation",
    }) };
  }
  if (input.capture === undefined) {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "committed",
      errorCode: null,
    }) };
  }
  try {
    const evidence = await input.capture();
    assertExactKeys(evidence, ["artifactRef", "contentHash"], "captureEvidence");
    assertSafeArtifactRef(evidence.artifactRef);
    assertSha256(evidence.contentHash, "contentHash");
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "committed",
      errorCode: null,
      artifactRefSha256: await sha256Hex(evidence.artifactRef),
      contentHash: evidence.contentHash,
      evidenceStatus: "captured",
    }) };
  } catch {
    return { kind: "recorded", receipt: await input.ledger.finalize(claim.handle, {
      status: "committed",
      errorCode: null,
      evidenceStatus: "capture_failed",
      evidenceErrorCode: "capture_failed",
    }) };
  }
}
