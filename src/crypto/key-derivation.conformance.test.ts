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
 * One seed materializing the whole composite identity, against the contract.
 *
 * This is the root of every signature this SDK produces. A divergence here is not
 * a wrong digest somewhere downstream — it is a different IDENTITY, signing
 * artifacts that resolve to a key nobody else derives from the same seed. Nothing
 * later detects it, because everything later is internally consistent with the
 * wrong key.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, createPublicKey } from "node:crypto";
import { Buffer } from "node:buffer";
import assert from "node:assert/strict";
import test from "node:test";

import {
  P256_DERIVE_INFO,
  signingKeyFromSeed,
  publicKeySec1UncompressedB64,
} from "./ecdsa-p256.js";
import { keygenMlDsa65 } from "./ml-dsa.js";
import { siblingPath } from "../test-support/siblings.js";

function doc(): any | null {
  const path = join(
    siblingPath(import.meta.url, "certcrypt-conformance", "fixtures", "primitives"),
    "key-derivation",
    "vectors.json"
  );
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

/** SEC1 uncompressed bytes of the public half, as the contract pins them. */
function uncompressed(seedHex: string): Buffer {
  const sk = signingKeyFromSeed(Buffer.from(seedHex, "hex"));
  return Buffer.from(publicKeySec1UncompressedB64(createPublicKey(sk)), "base64");
}

test("the seed derives the contract's P-256 half", () => {
  const v = doc();
  if (v === null) return; // the sibling guard reports absence, loudly

  for (const vec of v.vectors) {
    assert.equal(
      uncompressed(vec.seed_hex).toString("hex"),
      vec.p256_public_key_sec1_uncompressed_hex,
      `key-derivation '${vec.label}': P-256 uncompressed SEC1 diverged — the HKDF ` +
        `info string, the oversampling, or the mod-n reduction`
    );
  }
});

test("the seed derives the contract's ML-DSA-65 half", () => {
  const v = doc();
  if (v === null) return;

  for (const vec of v.vectors) {
    // The seed IS the FIPS 204 input: used verbatim as xi, with no KDF.
    const { publicKey } = keygenMlDsa65(Buffer.from(vec.seed_hex, "hex"));
    assert.equal(
      Buffer.from(publicKey).toString("base64"),
      vec.mldsa65_public_key_b64,
      `key-derivation '${vec.label}': ML-DSA-65 public key diverged — the seed must ` +
        `be used verbatim, with no domain separation`
    );
  }
});

test("the composite fingerprint is recomputed, not trusted", () => {
  const v = doc();
  if (v === null) return;

  for (const vec of v.vectors) {
    // Classical component FIRST, uncompressed. This is the
    // `system_root_fingerprint` an implementation must recompute rather than
    // accept, so a swapped root cannot pass as the published one.
    const { publicKey } = keygenMlDsa65(Buffer.from(vec.seed_hex, "hex"));
    const got = createHash("sha3-256")
      .update(uncompressed(vec.seed_hex))
      .update(Buffer.from(publicKey))
      .digest("hex");
    assert.equal(
      got,
      vec.composite_root_fingerprint,
      `key-derivation '${vec.label}': composite fingerprint diverged — component ` +
        `order, or the compressed SEC1 form used where the uncompressed one belongs`
    );
  }
});

test("the domain-separation string is the contract's", () => {
  const v = doc();
  if (v === null) return;
  // The info string is what keeps the two halves from deriving into each other.
  assert.equal(P256_DERIVE_INFO, "certcrypt/composite/p256/v1");
  assert.ok(
    v.rules.p256.includes(P256_DERIVE_INFO),
    "the contract's stated rule no longer names this info string"
  );
});
