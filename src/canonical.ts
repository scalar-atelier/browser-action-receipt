import type { JsonValue } from "./contract.js";

const MAX_DEPTH = 32;
const MAX_CONTAINER_ITEMS = 10_000;
const MAX_CANONICAL_BYTES = 128 * 1024;
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const HEX_SHA256 = /^[0-9a-f]{64}$/;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ISO_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export class ContractError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "ContractError";
    this.code = code;
  }
}

function encode(value: unknown, depth: number, seen: Set<object>): string {
  if (depth > MAX_DEPTH) {
    throw new ContractError("json_too_deep", `JSON exceeds depth ${MAX_DEPTH}`);
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ContractError("json_number_invalid", "Only safe integers are accepted");
    }
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value !== "object") {
    throw new ContractError("json_type_invalid", "Value is not plain JSON");
  }
  if (seen.has(value)) {
    throw new ContractError("json_cycle", "Cyclic JSON is not accepted");
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      if (value.length > MAX_CONTAINER_ITEMS) {
        throw new ContractError("json_too_many_items", "Array is too large");
      }
      return `[${value.map((item) => encode(item, depth + 1, seen)).join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new ContractError("json_prototype_invalid", "Object must have a plain prototype");
    }
    const object = value as Record<string, unknown>;
    for (const key of Reflect.ownKeys(object)) {
      const descriptor = Object.getOwnPropertyDescriptor(object, key);
      if (
        typeof key !== "string" ||
        descriptor === undefined ||
        !descriptor.enumerable ||
        !("value" in descriptor)
      ) {
        throw new ContractError("json_property_invalid", "Only enumerable data properties are accepted");
      }
    }
    const keys = Object.keys(object).sort();
    if (keys.length > MAX_CONTAINER_ITEMS) {
      throw new ContractError("json_too_many_items", "Object is too large");
    }
    for (const key of keys) {
      if (FORBIDDEN_KEYS.has(key)) {
        throw new ContractError("json_key_forbidden", `Forbidden key: ${key}`);
      }
    }
    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${encode(object[key], depth + 1, seen)}`)
      .join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

export function canonicalJson(value: unknown): string {
  const result = encode(value, 0, new Set());
  if (new TextEncoder().encode(result).byteLength > MAX_CANONICAL_BYTES) {
    throw new ContractError("json_too_large", `Canonical JSON exceeds ${MAX_CANONICAL_BYTES} bytes`);
  }
  return result;
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}

export function cloneFrozenJson(value: unknown): JsonValue {
  return deepFreeze(JSON.parse(canonicalJson(value)) as JsonValue);
}

export function assertSha256(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !HEX_SHA256.test(value)) {
    throw new ContractError("sha256_invalid", `${field} must be lowercase SHA-256 hex`);
  }
}

export function assertIsoTimestamp(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !ISO_MILLIS.test(value)) {
    throw new ContractError("timestamp_invalid", `${field} must be an ISO timestamp with milliseconds`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new ContractError("timestamp_invalid", `${field} is not a valid timestamp`);
  }
}

export function isoNow(now: Date = new Date()): string {
  const result = now.toISOString();
  assertIsoTimestamp(result, "timestamp");
  return result;
}

export function assertOperationId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !UUID_V4.test(value)) {
    throw new ContractError("operation_id_invalid", "operationId must be a lowercase UUID v4");
  }
}

export function assertExactKeys(
  value: unknown,
  keys: readonly string[],
  field: string,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ContractError("shape_invalid", `${field} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ContractError("shape_invalid", `${field} must have a plain prototype`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new ContractError("shape_invalid", `${field} has unexpected fields`);
  }
}

export function assertSafeArtifactRef(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(value)) {
    throw new ContractError("artifact_ref_invalid", "artifactRef must be an opaque safe token");
  }
}
