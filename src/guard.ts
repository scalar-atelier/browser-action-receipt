import { randomBytes, randomUUID } from "node:crypto";
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
import { equalSha256, sha256Hex } from "./node-crypto.js";
import type { ReceiptLedger } from "./ledger-contract.js";
import { assertTargetObservation, observationsMatch, receiptTarget } from "./receipt.js";

const ACTION_SET = new Set<string>(ACTIONS);
const RISK_SET = new Set<string>(RISK_CLASSES);
const MAX_FINGERPRINT_BYTES = 64 * 1024;
const MAX_APPROVAL_TTL_MS = 10 * 60 * 1000;

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

const preparedActions = new WeakMap<PreparedActionHandle, PreparedInternal>();

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

export interface ExecutePreparedActionInput {
  readonly prepared: PreparedActionHandle;
  readonly decision?: ApprovalDecisionV1;
  readonly adapter: AtomicActionAdapter;
  readonly ledger: ReceiptLedger;
  readonly capture?: CaptureEvidence;
  readonly now?: Date;
}

interface ApprovalEvaluation {
  readonly projection: BrowserActionReceiptV1["approval"];
  readonly blockCode: string | null;
}

function frozenObservation(observation: TargetObservationV1): TargetObservationV1 {
  assertTargetObservation(observation);
  return Object.freeze({ ...observation });
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

export function createTargetObservation(input: CreateObservationInput): TargetObservationV1 {
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
    pathnameSha256: sha256Hex(parsed.pathname),
    targetFingerprintSha256: sha256Hex(input.targetFingerprint),
    pageGeneration: input.pageGeneration,
    observedAt: input.observedAt ?? isoNow(),
  };
  assertTargetObservation(observation);
  return Object.freeze(observation);
}

export function prepareAction(input: PrepareActionInput): PreparedActionHandle {
  if (!ACTION_SET.has(input.action)) throw new ContractError("action_invalid", "Unknown browser action");
  if (!RISK_SET.has(input.riskClass)) throw new ContractError("risk_invalid", "Unknown risk class");
  const operationId = input.operationId ?? randomUUID();
  assertOperationId(operationId);
  const now = input.now ?? new Date();
  const preparedAt = isoNow(now);
  const ttl = input.approvalTtlMs ?? 120_000;
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > MAX_APPROVAL_TTL_MS) {
    throw new ContractError("approval_ttl_invalid", "approvalTtlMs is outside 1..600000");
  }
  const observation = frozenObservation(input.observation);
  const payload = cloneFrozenJson(input.payload);
  const display = approvalDisplay(input.approvalDisplay);
  const bindingNonce = randomBytes(32).toString("base64url");
  const bindingSha256 = sha256Hex(
    canonicalJson({
      operationId,
      action: input.action,
      riskClass: input.riskClass,
      observation,
      payload,
      display,
      bindingNonce,
    }),
  );
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
  const decidedAt = isoNow(options.now ?? new Date());
  return Object.freeze({
    schemaVersion: "browser-approval-decision/v1",
    operationId: request.operationId,
    bindingSha256: request.bindingSha256,
    decision,
    channel: options.channel ?? "host",
    decidedAt,
    expiresAt: request.expiresAt,
  });
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

function evaluateApproval(
  prepared: PreparedInternal,
  decision: ApprovalDecisionV1 | undefined,
  now: Date,
): ApprovalEvaluation {
  const currentTime = isoNow(now);
  if (currentTime < prepared.preparedAt) {
    return {
      projection: {
        decision: "invalid",
        channel: null,
        decidedAt: null,
        bindingSha256: prepared.bindingSha256,
      },
      blockCode: "clock_invalid",
    };
  }
  if (decision === undefined) {
    return {
      projection: {
        decision: "invalid",
        channel: null,
        decidedAt: null,
        bindingSha256: prepared.bindingSha256,
      },
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
      projection: {
        decision: "invalid",
        channel: null,
        decidedAt: null,
        bindingSha256: prepared.bindingSha256,
      },
      blockCode: "approval_invalid",
    };
  }

  if (currentTime > prepared.expiresAt) {
    return {
      projection: {
        decision: "expired",
        channel: decision.channel,
        decidedAt: decision.decidedAt,
        bindingSha256: prepared.bindingSha256,
      },
      blockCode: "approval_expired",
    };
  }
  if (decision.decision === "denied") {
    return {
      projection: {
        decision: "denied",
        channel: decision.channel,
        decidedAt: decision.decidedAt,
        bindingSha256: prepared.bindingSha256,
      },
      blockCode: "approval_denied",
    };
  }
  return {
    projection: {
      decision: "approved",
      channel: decision.channel,
      decidedAt: decision.decidedAt,
      bindingSha256: prepared.bindingSha256,
    },
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
    target: receiptTarget(prepared.observation),
    preparedAt: prepared.preparedAt,
    claimedAt: isoNow(now < new Date(prepared.preparedAt) ? new Date(prepared.preparedAt) : now),
  });

  const claim = await input.ledger.claim(seed);
  if (claim.kind !== "claimed") return claim;
  const claimHandle = claim.handle;

  if (approval.blockCode !== null) {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "blocked",
        errorCode: approval.blockCode,
      }),
    };
  }

  let rawActionResult: unknown;
  try {
    rawActionResult = await input.adapter.compareAndAct({
      action: prepared.action,
      payload: prepared.payload,
      expected: prepared.observation,
    });
  } catch {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "unknown_after_adapter",
        errorCode: "adapter_threw",
      }),
    };
  }

  try {
    assertAtomicActionResult(rawActionResult);
  } catch {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "unknown_after_adapter",
        errorCode: "adapter_contract_violation",
      }),
    };
  }
  const actionResult = rawActionResult;

  const matches = observationsMatch(prepared.observation, actionResult.observation);
  if (actionResult.status === "target_changed") {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: matches ? "unknown_after_adapter" : "aborted_target_changed",
        errorCode: matches ? "adapter_contract_violation" : "target_changed",
      }),
    };
  }
  if (!matches) {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "unknown_after_adapter",
        errorCode: "adapter_contract_violation",
      }),
    };
  }

  if (input.capture === undefined) {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "committed",
        errorCode: null,
      }),
    };
  }
  try {
    const evidence = await input.capture();
    assertExactKeys(evidence, ["artifactRef", "contentHash"], "captureEvidence");
    assertSafeArtifactRef(evidence.artifactRef);
    assertSha256(evidence.contentHash, "contentHash");
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "committed",
        errorCode: null,
        artifactRefSha256: sha256Hex(evidence.artifactRef),
        contentHash: evidence.contentHash,
        evidenceStatus: "captured",
      }),
    };
  } catch {
    return {
      kind: "recorded",
      receipt: await input.ledger.finalize(claimHandle, {
        status: "committed",
        errorCode: null,
        evidenceStatus: "capture_failed",
        evidenceErrorCode: "capture_failed",
      }),
    };
  }
}
