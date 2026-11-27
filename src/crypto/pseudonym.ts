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
 * Operation-scoped pseudonyms — issuer-side mirror of the reference verifier,
 * ported byte-for-byte (CCCP/1):
 *
 *   pseudonym(field) = SHA3-256( frame(operation_salt) || frame(domain_tag) || frame(stable_id) )
 *
 * Each field is absorbed with an 8-byte big-endian length prefix (framing) so
 * field boundaries are unambiguous — without this, ("ab","c") and ("a","bc")
 * would collide. 32-byte output, lowercase hex.
 *
 * Hash: SHA3-256 (FIPS 202 fixed-output), not SHAKE-256 — the output is a fixed
 * 32 bytes, so the XOF buys nothing.
 *
 * Parity is pinned by the published conformance vectors
 * (`fixtures/primitives/pseudonym`).
 */

import { createHash } from "node:crypto";

export type PseudonymDomain = "holder" | "pool" | "authorization";

/** Absorb a field with an 8-byte big-endian length prefix. */
function frame(field: Uint8Array): Buffer {
  const len = Buffer.alloc(8);
  len.writeBigUInt64BE(BigInt(field.length));
  return Buffer.concat([len, Buffer.from(field)]);
}

/**
 * Derive an operation-scoped pseudonym. `operationSalt` is the public
 * per-operation salt carried in the evidence; `domain` separates namespaces;
 * `stableId` is the identifier being projected; the capacity evidence carries
 * only its pseudonym.
 */
export function derivePseudonym(
  operationSalt: Uint8Array,
  domain: PseudonymDomain,
  stableId: string
): string {
  const h = createHash("sha3-256");
  h.update(frame(operationSalt));
  h.update(frame(new TextEncoder().encode(domain)));
  h.update(frame(new TextEncoder().encode(stableId)));
  return h.digest("hex");
}
