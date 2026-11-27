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
 * ML-DSA-65 (FIPS 204) signing for issuer-side Level-3 commitment signing.
 *
 * Backed by `@noble/post-quantum`. The issuer signs the canonical bytes of the
 * projected commitment with a per-operation leaf key of its operation-key tree.
 *
 * Byte contract — every implementation of the protocol MUST agree on this:
 *   - EMPTY context (no `context` option passed to sign);
 *   - pure ML-DSA-65 (FIPS 204), no pre-hash; arg order `sign(msg, secretKey)`.
 *
 * The signature travels as `commitment_signature_b64` in `capacity.evidence/1`,
 * with no algorithm identifier: that profile fixes pure ML-DSA-65.
 */
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

/**
 * Sign a message with an ML-DSA-65 holder secret key.
 *
 * @param secretKey raw ML-DSA-65 secret-key bytes
 * @param msg       the message bytes to sign (JCS canonical signing bytes)
 * @returns         raw ML-DSA-65 signature bytes
 */
export function signMlDsa65(secretKey: Uint8Array, msg: Uint8Array): Uint8Array {
  // arg order is (msg, secretKey); no context option => empty context.
  return ml_dsa65.sign(msg, secretKey);
}

/**
 * Verify an ML-DSA-65 signature. Provided for local self-checks and tests; the
 * production verification path lives in the verifier toolkit / the server.
 *
 * @param publicKey raw ML-DSA-65 public-key bytes
 * @param msg       the signed message bytes
 * @param sig       raw ML-DSA-65 signature bytes
 */
export function verifyMlDsa65(
  publicKey: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array
): boolean {
  return ml_dsa65.verify(sig, msg, publicKey);
}

/**
 * Generate an ML-DSA-65 keypair. For development and tests: in normal use the
 * operation-key tree is derived from the issuer's own master seed via
 * `HolderKeySet.fromMasterSeed`, so keys are never generated ad hoc.
 *
 * @param seed optional 32-byte seed for deterministic keygen
 */
export function keygenMlDsa65(seed?: Uint8Array): {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
} {
  return ml_dsa65.keygen(seed);
}
