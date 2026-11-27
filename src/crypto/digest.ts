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
 * SHA3-256 digesting over node:crypto.
 *
 * Mirrors certcrypt-verifier-toolkit-js/core/crypto/digest.ts so the issuer
 * computes the same deterministic identifiers (commitment_id, submission_set_id)
 * the verifier and the server recompute (sha3_256_hex over JCS canonical bytes).
 */
import { createHash } from "node:crypto";

export function digestHexBytes(data: Uint8Array): string {
  return createHash("sha3-256").update(data).digest("hex");
}

export function digestHexText(text: string): string {
  return createHash("sha3-256").update(text, "utf-8").digest("hex");
}

export function digestBytes(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha3-256").update(data).digest());
}
