// Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Per CCCP/1: the canonical form for payload signing uses RFC 8785.
 * This means lexicographic key ordering, no extra whitespace,
 * and deterministic number serialization.
 *
 * Copied verbatim from certcrypt-verifier-toolkit-js/core/crypto/jcs.ts so the
 * issuer-side canonical bytes match the verifier's byte-for-byte. The toolkit
 * does not export this module, so it is vendored here rather than imported.
 */
export function jcsCanonicalizeBytes(obj: unknown): Uint8Array {
  const canonical = jcsStringify(obj);
  return new TextEncoder().encode(canonical);
}

export function jcsCanonicalizeString(obj: unknown): string {
  return jcsStringify(obj);
}

function jcsStringify(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "null";

  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    // RFC 8785: use ECMAScript Number.toString() serialization
    if (!isFinite(value as number)) {
      throw new Error("JCS does not support Infinity or NaN");
    }
    return String(value);
  }

  if (t === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map((v) => jcsStringify(v));
    return "[" + items.join(",") + "]";
  }

  if (t === "object" && value !== null) {
    const obj = value as Record<string, unknown>;
    // RFC 8785: sort keys lexicographically by Unicode code point
    const keys = Object.keys(obj).sort();
    const members = keys
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + jcsStringify(obj[k]));
    return "{" + members.join(",") + "}";
  }

  throw new Error(`JCS: unsupported type ${t}`);
}
