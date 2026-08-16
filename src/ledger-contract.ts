import type { BrowserActionReceiptV1, ReceiptSeedV1 } from "./contract.js";
import type { ReceiptResultInput } from "./receipt.js";

export interface ClaimHandle {
  readonly operationId: string;
}

export type ClaimOutcome =
  | { readonly kind: "claimed"; readonly handle: ClaimHandle }
  | { readonly kind: "duplicate_final"; readonly receipt: BrowserActionReceiptV1 }
  | { readonly kind: "duplicate_in_progress"; readonly operationId: string }
  | { readonly kind: "operation_conflict"; readonly operationId: string };

export interface ReceiptLedger {
  claim(seed: ReceiptSeedV1): Promise<ClaimOutcome>;
  finalize(
    handle: ClaimHandle,
    result: ReceiptResultInput,
    finalizedAt?: string,
  ): Promise<BrowserActionReceiptV1>;
}
