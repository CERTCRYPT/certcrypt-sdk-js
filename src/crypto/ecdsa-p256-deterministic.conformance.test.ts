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
 * The ECDSA P-256 signature itself, against the contract.
 *
 * Conformance family `ecdsa-p256-deterministic`: SHA3-256 prehash, RFC 6979
 * nonce with HMAC-SHA3-256, low-s, raw r||s. Every verifier accepts any valid
 * low-s signature, so a nonce that drifts never fails a verification; it only
 * makes this SDK's signatures stop being reproducible. Exact equality is the
 * only check that sees it, so every signature here is compared byte for byte.
 */

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import type { KeyObject } from "node:crypto";
import test from "node:test";

import { deriveIssuerKey } from "../artifacts/base-certificate.js";
import { compositeSignP256 } from "./composite.js";
import {
  privateKeyFromScalar,
  publicKeyB64FromPrivate,
  signEcdsaP256Raw,
  signingKeyFromSeed,
  verifyEcdsaP256Raw,
} from "./ecdsa-p256.js";
import { keygenMlDsa65 } from "./ml-dsa.js";
import { missingSibling, siblingPath } from "../test-support/siblings.js";

const FIXTURE = ["fixtures", "primitives", "ecdsa-p256-deterministic", "vectors.json"];
const skip = missingSibling(import.meta.url, "certcrypt-conformance", ...FIXTURE);

function doc(): any {
  return JSON.parse(
    readFileSync(siblingPath(import.meta.url, "certcrypt-conformance", ...FIXTURE), "utf-8")
  );
}

const hex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** The key a vector names, derived the way this SDK derives it in use. */
function keyOf(k: any): KeyObject {
  switch (k.source) {
    case "issuer-key-derivation":
      return deriveIssuerKey(k.master_seed_hex, "conformance").p256Private;
    case "key-derivation":
      return signingKeyFromSeed(hex(k.seed_hex));
    case "scalar":
      return privateKeyFromScalar(hex(k.scalar_hex));
    default:
      throw new Error(`unknown key source ${k.source}`);
  }
}

test("the profile is the one this SDK implements", { skip }, () => {
  assert.equal(doc().profile, "ecdsa-p256-deterministic/1");
});

test("every key derives the contract's public key", { skip }, () => {
  for (const [ref, k] of Object.entries<any>(doc().keys)) {
    assert.equal(publicKeyB64FromPrivate(keyOf(k)), k.expected_pub_p256_b64, ref);
    // The written-out scalar is the same key: signing from it must not differ.
    assert.equal(
      publicKeyB64FromPrivate(privateKeyFromScalar(hex(k.scalar_hex))),
      k.expected_pub_p256_b64,
      `${ref}: scalar_hex`
    );
  }
});

test("every signature matches the contract byte for byte", { skip }, () => {
  const d = doc();
  for (const v of d.vectors) {
    const k = d.keys[v.key];
    const msg = hex(v.message_hex);
    if (v.message_utf8 !== undefined) {
      assert.equal(toHex(new TextEncoder().encode(v.message_utf8)), v.message_hex, v.name);
    }
    const sig = signEcdsaP256Raw(keyOf(k), msg);
    assert.equal(toHex(sig), v.expected_sig_hex, v.name);
    assert.equal(Buffer.from(sig).toString("base64"), v.expected_sig_b64, v.name);
    assert.ok(verifyEcdsaP256Raw(k.expected_pub_p256_b64, msg, sig), `${v.name}: verifies`);
    // Signing again changes nothing: there is no nonce left to vary.
    assert.equal(toHex(signEcdsaP256Raw(keyOf(k), msg)), v.expected_sig_hex, `${v.name}: repeat`);
  }
});

test("both low-s branches are exercised", { skip }, () => {
  const flags = doc().vectors.map((v: any) => v.expected_low_s_applied);
  assert.ok(flags.includes(true) && flags.includes(false));
});

test("the composite's ECDSA component goes on the wire exactly as the contract says", { skip }, () => {
  const d = doc();
  // ML-DSA-65 is not pinned by this family; any secret key serves.
  const { secretKey } = keygenMlDsa65(new Uint8Array(32));
  for (const c of d.composite_cases) {
    const wire = compositeSignP256(c.payload_canon_digest_hex, {
      p256Private: keyOf(d.keys[c.key]),
      mldsaSecret: secretKey,
    });
    assert.equal(wire.alg, c.composite_alg_id, c.name);
    assert.deepEqual(wire.signatures[0], c.expected_ecdsa_component, c.name);
  }
});
