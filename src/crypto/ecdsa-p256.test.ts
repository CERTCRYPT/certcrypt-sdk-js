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
 * ECDSA P-256 — the classical half of the composite signature.
 *
 * `composite.test.ts` covers the joint signature. This file covers the key and
 * signature plumbing underneath, where the branches are input validation: a bad
 * scalar, a truncated signature, a malformed key. Each guard exists because the
 * alternative is worse than an exception:
 *
 *   - a scalar outside [1, n) is not a key, and letting one through would produce
 *     signatures nothing can verify;
 *   - a signature is raw r||s (64 bytes, IEEE P-1363), NOT DER — accepting the
 *     wrong encoding here is how cross-language verification silently dies;
 *   - `low-s` is NORMATIVE for the producer: both (r, s) and (r, n − s) are
 *     mathematically valid, so without the rule the same key over the same
 *     message yields two different valid signatures — malleability a verifier
 *     recomputing bytes cannot tolerate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import {
  generateEcdsaP256KeyPair,
  publicKeySec1UncompressedB64,
  privateKeyFromPkcs8,
  privateKeyFromScalar,
  scalarFromSeedMaterial,
  publicKeyB64FromPrivate,
  signEcdsaP256Raw,
  verifyEcdsaP256Raw,
} from "./ecdsa-p256.js";

/** secp256r1 group order, and the low-s ceiling. */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;

const message = new TextEncoder().encode("the message under signature");

function be32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function toBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

// --- round trip ------------------------------------------------------------

test("a generated keypair signs and verifies, and the wire key is SEC1 uncompressed", () => {
  const kp = generateEcdsaP256KeyPair();
  const raw = Buffer.from(kp.publicKeyB64, "base64");
  assert.equal(raw.length, 65, "SEC1 uncompressed is 65 bytes");
  assert.equal(raw[0], 0x04, "and 0x04-prefixed");

  const sig = signEcdsaP256Raw(kp.privateKey, message);
  assert.equal(sig.length, 64, "the wire signature is raw r||s, not DER");
  assert.ok(verifyEcdsaP256Raw(kp.publicKeyB64, message, sig));
});

test("publicKeyB64FromPrivate agrees with the pair's own wire key", () => {
  const kp = generateEcdsaP256KeyPair();
  assert.equal(publicKeyB64FromPrivate(kp.privateKey), kp.publicKeyB64);
});

test("a signature does not verify against another key, or another message", () => {
  const kp = generateEcdsaP256KeyPair();
  const other = generateEcdsaP256KeyPair();
  const sig = signEcdsaP256Raw(kp.privateKey, message);
  assert.ok(!verifyEcdsaP256Raw(other.publicKeyB64, message, sig), "wrong key must not verify");
  assert.ok(
    !verifyEcdsaP256Raw(kp.publicKeyB64, new TextEncoder().encode("tampered"), sig),
    "a different message must not verify"
  );
});

// --- low-s (normative for the producer) ------------------------------------

test("every produced signature is low-s", () => {
  // The producer MUST emit s ≤ n/2. Without it the same key over the same message
  // can yield two distinct valid signatures, and a verifier comparing bytes has no
  // way to know they are the same signature.
  for (let i = 0; i < 12; i++) {
    const kp = generateEcdsaP256KeyPair();
    const sig = signEcdsaP256Raw(kp.privateKey, new TextEncoder().encode(`msg-${i}`));
    const s = toBigInt(sig.subarray(32, 64));
    assert.ok(s <= HALF_N, `signature ${i} is high-s (s > n/2): malleable`);
  }
});

test("a HIGH-s signature is rejected even though it is mathematically valid", () => {
  // Flip a valid signature to its (r, n − s) twin. It verifies under plain ECDSA
  // math, so this is exactly the case a verifier must refuse on policy.
  const kp = generateEcdsaP256KeyPair();
  const sig = signEcdsaP256Raw(kp.privateKey, message);
  const s = toBigInt(sig.subarray(32, 64));
  const flipped = new Uint8Array(64);
  flipped.set(sig.subarray(0, 32), 0);
  flipped.set(be32(N - s), 32);
  assert.ok(!verifyEcdsaP256Raw(kp.publicKeyB64, message, flipped), "high-s must be refused");
});

test("a signature with r or s out of range is rejected, not thrown", () => {
  const kp = generateEcdsaP256KeyPair();
  const zero = new Uint8Array(64); // r = 0, s = 0
  assert.equal(verifyEcdsaP256Raw(kp.publicKeyB64, message, zero), false);

  const sig = signEcdsaP256Raw(kp.privateKey, message);
  const rTooBig = new Uint8Array(64);
  rTooBig.set(be32(N), 0); // r = n, out of [1, n)
  rTooBig.set(sig.subarray(32, 64), 32);
  assert.equal(verifyEcdsaP256Raw(kp.publicKeyB64, message, rTooBig), false);
});

test("a signature of the wrong length is rejected, not thrown", () => {
  // DER-encoded signatures land here in practice: they are ~70-72 bytes. Verify
  // must answer false rather than throw, so a caller cannot mistake a malformed
  // input for an infrastructure failure.
  const kp = generateEcdsaP256KeyPair();
  for (const len of [0, 63, 65, 71]) {
    assert.equal(verifyEcdsaP256Raw(kp.publicKeyB64, message, new Uint8Array(len)), false);
  }
});

// --- deterministic keys from a scalar --------------------------------------

test("the same scalar always yields the same key", () => {
  // Determinism is the point: an issuer re-derives its key from a seed on every
  // start, so the same scalar must give the same public key forever.
  const scalar = scalarFromSeedMaterial(new TextEncoder().encode("seed material"));
  const a = privateKeyFromScalar(scalar);
  const b = privateKeyFromScalar(scalar);
  assert.equal(publicKeyB64FromPrivate(a), publicKeyB64FromPrivate(b));

  // And it is a working key, not just a well-formed one.
  const sig = signEcdsaP256Raw(a, message);
  assert.ok(verifyEcdsaP256Raw(publicKeyB64FromPrivate(a), message, sig));
});

test("a scalar of the wrong length is refused", () => {
  for (const len of [0, 31, 33, 64]) {
    assert.throws(() => privateKeyFromScalar(new Uint8Array(len)), /must be 32 bytes/);
  }
});

test("a scalar outside [1, n) is refused", () => {
  // Zero and n itself are not private keys. Accepting either would produce a
  // KeyObject that cannot sign anything verifiable.
  assert.throws(() => privateKeyFromScalar(new Uint8Array(32)), /out of range/);
  assert.throws(() => privateKeyFromScalar(be32(N)), /out of range/);
  assert.throws(() => privateKeyFromScalar(be32(N + 1n)), /out of range/);
});

test("scalarFromSeedMaterial always lands in [1, n), including at the edges", () => {
  // It folds ARBITRARY bytes into range, so the interesting inputs are the ones
  // that would land on 0 or n without the +1 / mod (n−1).
  const cases: Uint8Array[] = [
    new Uint8Array(32), // all zeros
    be32(N - 1n),
    be32(N),
    be32(N + 1n),
    new Uint8Array(32).fill(0xff),
    new Uint8Array(0), // empty material
    new TextEncoder().encode("short"),
  ];
  for (const material of cases) {
    const scalar = scalarFromSeedMaterial(material);
    assert.equal(scalar.length, 32);
    const d = toBigInt(scalar);
    assert.ok(d >= 1n && d < N, `scalar ${d} is outside [1, n)`);
    // And it must be usable, which is the real assertion.
    assert.doesNotThrow(() => privateKeyFromScalar(scalar));
  }
});

test("scalarFromSeedMaterial is deterministic", () => {
  const material = new TextEncoder().encode("same input");
  assert.deepEqual(scalarFromSeedMaterial(material), scalarFromSeedMaterial(material));
});

// --- key import ------------------------------------------------------------

test("a PKCS#8 key round-trips (the KMS-provisioned path)", () => {
  const kp = generateEcdsaP256KeyPair();
  const pkcs8 = kp.privateKey.export({ format: "pem", type: "pkcs8" }) as string;
  const imported = privateKeyFromPkcs8(pkcs8);
  assert.equal(publicKeyB64FromPrivate(imported), kp.publicKeyB64);
  const sig = signEcdsaP256Raw(imported, message);
  assert.ok(verifyEcdsaP256Raw(kp.publicKeyB64, message, sig));
});

test("a non-P-256 public key is refused by the SEC1 exporter", () => {
  // The exporter assembles 0x04 || X(32) || Y(32) from JWK coordinates. A key from
  // another curve has coordinates of a different size, so the guard must fire
  // rather than emit a wrongly-sized wire key.
  const { publicKey } = generateKeyPairSync("ed25519");
  const ed = createPublicKey({
    key: publicKey.export({ format: "pem", type: "spki" }) as string,
    format: "pem",
  });
  assert.throws(() => publicKeySec1UncompressedB64(ed));
});
