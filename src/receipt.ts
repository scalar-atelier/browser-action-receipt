import {
  ACTIONS,
  RISK_CLASSES,
  type BrowserActionReceiptV1,
  type ReceiptSeedV1,
  type TargetObservationV1,
} from "./contract.js";
import {
  ContractError,
  assertExactKeys,
  assertIsoTimestamp,
  assertOperationId,
  assertSha256,
  canonicalJson,
} from "./canonical.js";
import { equalSha256, sha256Hex } from "./node-crypto.js";

const ACTION_SET = new Set<string>(ACTIONS);
const RISK_SET = new Set<string>(RISK_CLASSES);
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

export interface ReceiptResultInput {
  readonly status: BrowserActionReceiptV1["result"]["status"];
  readonly errorCode: string | null;
  readonly artifactRefSha256?: string | null;
  readonly contentHash?: string | null;
  readonly evidenceStatus?: BrowserActionReceiptV1["result"]["evidenceStatus"];
  readonly evidenceErrorCode?: string | null;
}

function assertString(value: unknown, field: string, max = 512): asserts value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) {
    throw new ContractError("field_invalid", `${field} must be a non-empty string`);
  }
}

export function assertTargetObservation(value: unknown): asserts value is TargetObservationV1 {
  assertExactKeys(
    value,
    [
      "schemaVersion",
      "origin",
      "pathnameSha256",
      "targetFingerprintSha256",
      "pageGeneration",
      "observedAt",
    ],
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

export function receiptTarget(observation: TargetObservationV1): BrowserActionReceiptV1["target"] {
  assertTargetObservation(observation);
  return Object.freeze({
    origin: observation.origin,
    pathnameSha256: observation.pathnameSha256,
    fingerprintSha256: observation.targetFingerprintSha256,
    pageGenerationSha256: sha256Hex(observation.pageGeneration),
  });
}

export function observationsMatch(left: TargetObservationV1, right: TargetObservationV1): boolean {
  assertTargetObservation(left);
  assertTargetObservation(right);
  return (
    left.origin === right.origin &&
    equalSha256(left.pathnameSha256, right.pathnameSha256) &&
    equalSha256(left.targetFingerprintSha256, right.targetFingerprintSha256) &&
    left.pageGeneration === right.pageGeneration
  );
}

export function assertReceiptSeed(value: unknown): asserts value is ReceiptSeedV1 {
  assertExactKeys(
    value,
    [
      "schemaVersion",
      "operationId",
      "action",
      "riskClass",
      "approval",
      "target",
      "preparedAt",
      "claimedAt",
    ],
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
  assertExactKeys(
    value,
    ["origin", "pathnameSha256", "fingerprintSha256", "pageGenerationSha256"],
    "target",
  );
  assertString(value.origin, "target.origin", 512);
  let parsed: URL;
  try {
    parsed = new URL(value.origin);
  } catch {
    throw new ContractError("origin_invalid", "target.origin must be a URL origin");
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.origin !== value.origin) {
    throw new ContractError("origin_invalid", "target.origin must be canonical HTTP(S)");
  }
  assertSha256(value.pathnameSha256, "target.pathnameSha256");
  assertSha256(value.fingerprintSha256, "target.fingerprintSha256");
  assertSha256(value.pageGenerationSha256, "target.pageGenerationSha256");
}

function assertResult(value: unknown): asserts value is BrowserActionReceiptV1["result"] {
  assertExactKeys(
    value,
    [
      "status",
      "errorCode",
      "artifactRefSha256",
      "contentHash",
      "evidenceStatus",
      "evidenceErrorCode",
    ],
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
  if (
    value.status !== "committed" &&
    !STATUS_ERROR_CODES[value.status]?.has(value.errorCode as string)
  ) {
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

export function buildReceipt(
  seed: ReceiptSeedV1,
  resultInput: ReceiptResultInput,
  finalizedAt: string,
): BrowserActionReceiptV1 {
  assertReceiptSeed(seed);
  assertIsoTimestamp(finalizedAt, "finalizedAt");
  const result: BrowserActionReceiptV1["result"] = {
    status: resultInput.status,
    errorCode: resultInput.errorCode,
    artifactRefSha256: resultInput.artifactRefSha256 ?? null,
    contentHash: resultInput.contentHash ?? null,
    evidenceStatus: resultInput.evidenceStatus ?? "not_requested",
    evidenceErrorCode:
      resultInput.evidenceErrorCode === null || resultInput.evidenceErrorCode === undefined
        ? null
        : resultInput.evidenceErrorCode,
  };
  assertResult(result);
  const withoutHash = {
    schemaVersion: "browser-action-receipt/v1" as const,
    operationId: seed.operationId,
    action: seed.action,
    riskClass: seed.riskClass,
    approval: seed.approval,
    target: seed.target,
    result,
    preparedAt: seed.preparedAt,
    finalizedAt,
  };
  const receipt = Object.freeze({
    ...withoutHash,
    receiptSha256: sha256Hex(canonicalJson(withoutHash)),
  });
  assertReceipt(receipt);
  return receipt;
}

export function assertReceipt(value: unknown): asserts value is BrowserActionReceiptV1 {
  assertExactKeys(
    value,
    [
      "schemaVersion",
      "operationId",
      "action",
      "riskClass",
      "approval",
      "target",
      "result",
      "preparedAt",
      "finalizedAt",
      "receiptSha256",
    ],
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
  const { receiptSha256, ...withoutHash } = value;
  if (!equalSha256(receiptSha256, sha256Hex(canonicalJson(withoutHash)))) {
    throw new ContractError("receipt_hash_mismatch", "Receipt hash does not match its contents");
  }
}

export function parseReceipt(text: string): BrowserActionReceiptV1 {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ContractError("receipt_json_invalid", "Receipt is not valid JSON");
  }
  assertReceipt(value);
  return value;
}
