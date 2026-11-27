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
 * The composite M′ framing, against the contract.
 *
 * A comment saying `compositeMPrime` "mirrors the toolkit exactly" is a promise,
 * not a check; this file is the check, and this SDK is where the signature is
 * MADE. If its framing drifts, every certificate it mints is signed
 * over a message no verifier reconstructs — and this SDK's own tests keep passing,
 * because it verifies nothing.
 *
 * This is the last step both components share. The ECDSA component over M′ is
 * pinned too, by `ecdsa-p256-deterministic` (RFC 6979); ML-DSA here is hedged and
 * cannot be, so for that half M′ is where the byte contract stops.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import { compositeMPrime, PROFILE_P256_MLDSA65 } from "./composite.js";
import { siblingPath } from "../test-support/siblings.js";

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** The contract's `composite-m-prime` vectors, or null when not checked out. */
function vectors(): any | null {
  const path = siblingPath(
    import.meta.url,
    "certcrypt-conformance",
    "fixtures",
    "primitives",
    "composite-m-prime",
    "vectors.json"
  );
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

test("M′ framing matches the contract byte-for-byte", () => {
  const v = vectors();
  if (v === null) return; // the sibling guard reports absence, loudly

  for (const vec of v.vectors) {
    const m = compositeMPrime(vec.composite_alg_id, vec.payload_canon_digest_hex);
    assert.equal(
      toHex(m),
      vec.expected_m_prime_hex,
      `composite-m-prime '${vec.label}': framing diverged — domain prefix, separators, ` +
        `or the order of the parts`
    );
    assert.equal(
      m.length,
      vec.expected_m_prime_len,
      `composite-m-prime '${vec.label}': length diverged`
    );
  }
});

test("the composite profile changes M′", () => {
  // The property the profile is in the framing FOR. Without it, a signature this
  // SDK makes under one profile could be reinterpreted under another.
  const digest = "a".repeat(64);
  assert.notEqual(
    toHex(compositeMPrime(PROFILE_P256_MLDSA65, digest)),
    toHex(compositeMPrime("certcrypt-composite-ed25519-mldsa65-v1", digest)),
    "omitting the profile from the framing makes a signature reinterpretable across profiles"
  );
});

test("the digest is framed as text, not as its raw bytes", () => {
  // The natural wrong guess: the hex string DENOTES 32 bytes, so an implementation
  // may reach for those instead. M′ would then be 32 bytes shorter and verify
  // nowhere. Derived from the contract's own vector rather than asserted here.
  const v = vectors();
  if (v === null) return;
  const vec = v.vectors[0];
  const m = compositeMPrime(vec.composite_alg_id, vec.payload_canon_digest_hex);
  assert.ok(
    m.length > vec.payload_canon_digest_hex.length,
    "M′ must contain the digest's 64 hex characters, not its 32 raw bytes"
  );
  assert.ok(
    toHex(m).endsWith(Buffer.from(vec.payload_canon_digest_hex, "utf-8").toString("hex")),
    "M′ must end with the digest as UTF-8 text"
  );
});
