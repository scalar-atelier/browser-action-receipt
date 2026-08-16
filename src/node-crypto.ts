import { createHash, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";

const HEX_SHA256 = /^[0-9a-f]{64}$/;

export function sha256Hex(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

export function equalSha256(left: string, right: string): boolean {
  if (!HEX_SHA256.test(left) || !HEX_SHA256.test(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}
