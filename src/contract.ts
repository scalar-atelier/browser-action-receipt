export const ACTIONS = ["click", "type", "select", "submit"] as const;
export const RISK_CLASSES = ["R0", "R1", "R2", "R3"] as const;

export type BrowserAction = (typeof ACTIONS)[number];
export type RiskClass = (typeof RISK_CLASSES)[number];
export type JsonPrimitive = null | boolean | string | number;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface TargetObservationV1 {
  readonly schemaVersion: "browser-target-observation/v1";
  readonly origin: string;
  readonly pathnameSha256: string;
  readonly targetFingerprintSha256: string;
  readonly pageGeneration: string;
  readonly observedAt: string;
}

export interface ApprovalRequestV1 {
  readonly schemaVersion: "browser-approval-request/v1";
  readonly operationId: string;
  readonly action: BrowserAction;
  readonly riskClass: RiskClass;
  readonly origin: string;
  readonly display: {
    readonly title: string;
    readonly detail: string;
  };
  readonly bindingSha256: string;
  readonly expiresAt: string;
}

export interface ApprovalDecisionV1 {
  readonly schemaVersion: "browser-approval-decision/v1";
  readonly operationId: string;
  readonly bindingSha256: string;
  readonly decision: "approved" | "denied";
  readonly channel: "host" | "native";
  readonly decidedAt: string;
  readonly expiresAt: string;
}

export interface PreparedActionHandle {
  readonly operationId: string;
  readonly action: BrowserAction;
  readonly riskClass: RiskClass;
  readonly approvalRequest: ApprovalRequestV1;
}

export interface BrowserActionReceiptV1 {
  readonly schemaVersion: "browser-action-receipt/v1";
  readonly operationId: string;
  readonly action: BrowserAction;
  readonly riskClass: RiskClass;
  readonly approval: {
    readonly decision: "approved" | "denied" | "expired" | "invalid";
    readonly channel: "host" | "native" | null;
    readonly decidedAt: string | null;
    readonly bindingSha256: string;
  };
  readonly target: {
    readonly origin: string;
    readonly pathnameSha256: string;
    readonly fingerprintSha256: string;
    readonly pageGenerationSha256: string;
  };
  readonly result: {
    readonly status:
      | "committed"
      | "blocked"
      | "aborted_target_changed"
      | "unknown_after_claim"
      | "unknown_after_adapter";
    readonly errorCode: string | null;
    readonly artifactRefSha256: string | null;
    readonly contentHash: string | null;
    readonly evidenceStatus: "captured" | "not_requested" | "capture_failed";
    readonly evidenceErrorCode: string | null;
  };
  readonly preparedAt: string;
  readonly finalizedAt: string;
  readonly receiptSha256: string;
}

export interface AtomicActionInput {
  readonly action: BrowserAction;
  readonly payload: JsonValue;
  readonly expected: TargetObservationV1;
}

export type AtomicActionResult =
  | { readonly status: "committed"; readonly observation: TargetObservationV1 }
  | { readonly status: "target_changed"; readonly observation: TargetObservationV1 };

export interface AtomicActionAdapter {
  readonly capability: "atomic-compare-and-act/v1";
  compareAndAct(input: AtomicActionInput): Promise<AtomicActionResult>;
}

export interface CaptureEvidenceV1 {
  readonly artifactRef: string;
  readonly contentHash: string;
}

export type CaptureEvidence = () => Promise<CaptureEvidenceV1>;

export type ExecutionOutcome =
  | { readonly kind: "recorded"; readonly receipt: BrowserActionReceiptV1 }
  | { readonly kind: "duplicate_final"; readonly receipt: BrowserActionReceiptV1 }
  | { readonly kind: "duplicate_in_progress"; readonly operationId: string }
  | { readonly kind: "operation_conflict"; readonly operationId: string };

/** @internal Claim seed contains only fields allowed in a durable receipt. */
export interface ReceiptSeedV1 {
  readonly schemaVersion: "browser-action-claim/v1";
  readonly operationId: string;
  readonly action: BrowserAction;
  readonly riskClass: RiskClass;
  readonly approval: BrowserActionReceiptV1["approval"];
  readonly target: BrowserActionReceiptV1["target"];
  readonly preparedAt: string;
  readonly claimedAt: string;
}
