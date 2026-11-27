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
 * Cross-implementation interop for the composite signer: a signature produced by
 * the SDK MUST verify under the verifier-toolkit's `verifyComposite` (the real
 * trust verdict). This is the gold interoperability check — if M', low-s, the
 * component order, or the wire shape diverge, the toolkit rejects it.
 *
 * The toolkit is imported by absolute path to its compiled output (its package
 * `exports` map does not expose the composite module).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve, dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { siblingPath, missingSibling } from "../test-support/siblings.js";
import {
  compositeMPrime,
  compositeSignP256,
  PROFILE_P256_MLDSA65,
} from "./composite.js";
import {
  generateEcdsaP256KeyPair,
  signEcdsaP256Raw,
  verifyEcdsaP256Raw,
} from "./ecdsa-p256.js";
import { keygenMlDsa65 } from "./ml-dsa.js";

const TOOLKIT_DIST = siblingPath(
  import.meta.url,
  "certcrypt-verifier-toolkit-js", "dist", "core", "crypto"
);
const skip = missingSibling(
  import.meta.url,
  "certcrypt-verifier-toolkit-js", "dist", "core", "crypto"
);

async function loadToolkitComposite(): Promise<any> {
  // The toolkit's ML-DSA backend is lazy-loaded and MUST be initialized once
  // before any synchronous verifyComposite call, or it reports unsupported_runtime.
  const mldsa = await import(pathToFileURL(resolve(TOOLKIT_DIST, "ml-dsa.js")).href);
  const ok = await mldsa.initMlDsa65();
  if (!ok) throw new Error("toolkit ML-DSA-65 backend unavailable (initMlDsa65 failed)");
  return import(pathToFileURL(resolve(TOOLKIT_DIST, "composite.js")).href);
}

test("compositeMPrime matches the toolkit byte-for-byte", {skip}, async () => {
  const toolkit = await loadToolkitComposite();
  const digest = "1c793b940a153b736903bbefb286e8654f34797606292ad629173c72c5f50275";
  const ours = compositeMPrime(PROFILE_P256_MLDSA65, digest);
  const theirs: Uint8Array = toolkit.compositeMPrime(PROFILE_P256_MLDSA65, digest);
  assert.equal(Buffer.from(ours).toString("hex"), Buffer.from(theirs).toString("hex"));
});

test("ECDSA-P256 raw-rs-64 sign→verify round-trips (low-s)", () => {
  const kp = generateEcdsaP256KeyPair();
  const msg = new TextEncoder().encode("composite message M'");
  const sig = signEcdsaP256Raw(kp.privateKey, msg);
  assert.equal(sig.length, 64);
  assert.ok(verifyEcdsaP256Raw(kp.publicKeyB64, msg, sig), "self-verify");
  // low-s: s (second half) must be ≤ n/2. Our verify rejects high-s, so a pass
  // here already implies low-s; assert explicitly for clarity.
  const P256_HALF_N =
    (0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n) >> 1n;
  let s = 0n;
  for (const b of sig.subarray(32, 64)) s = (s << 8n) | BigInt(b);
  assert.ok(s <= P256_HALF_N, "signature is low-s");
});

test("SDK composite signature verifies under the toolkit's verifyComposite", {skip}, async () => {
  const toolkit = await loadToolkitComposite();

  const p256 = generateEcdsaP256KeyPair();
  const mldsa = keygenMlDsa65();
  const payloadCanonDigestHex =
    "1c793b940a153b736903bbefb286e8654f34797606292ad629173c72c5f50275";

  const wire = compositeSignP256(payloadCanonDigestHex, {
    p256Private: p256.privateKey,
    mldsaSecret: mldsa.secretKey,
  });

  // Shape assertions : classical first, encoding/low_s on ECDSA only.
  assert.equal(wire.alg, PROFILE_P256_MLDSA65);
  assert.equal(wire.mode, "AND");
  assert.equal(wire.signatures[0].alg, "ECDSA-P256-SHA3-256");
  assert.equal(wire.signatures[0].encoding, "raw-rs-64");
  assert.equal(wire.signatures[0].low_s, true);
  assert.equal(wire.signatures[1].alg, "ML-DSA-65");
  assert.equal(wire.signatures[1].encoding, undefined);

  const result = toolkit.verifyComposite(
    PROFILE_P256_MLDSA65,
    payloadCanonDigestHex,
    wire,
    {
      classicalPubB64: p256.publicKeyB64,
      mldsaPubB64: Buffer.from(mldsa.publicKey).toString("base64"),
    }
  );

  assert.ok(result.valid, `composite must verify: ${JSON.stringify(result)}`);
  assert.equal(result.classical.passed, true);
  assert.equal(result.mldsa.passed, true);
});

test("toolkit rejects a composite signed over a different digest", {skip}, async () => {
  const toolkit = await loadToolkitComposite();
  const p256 = generateEcdsaP256KeyPair();
  const mldsa = keygenMlDsa65();
  const wire = compositeSignP256("a".repeat(64), {
    p256Private: p256.privateKey,
    mldsaSecret: mldsa.secretKey,
  });
  const result = toolkit.verifyComposite(PROFILE_P256_MLDSA65, "b".repeat(64), wire, {
    classicalPubB64: p256.publicKeyB64,
    mldsaPubB64: Buffer.from(mldsa.publicKey).toString("base64"),
  });
  assert.equal(result.valid, false);
});
