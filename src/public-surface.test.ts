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
 * The package's public surface: what an integrator may import, and what it must
 * not be able to.
 *
 * A composite signature is valid only as the AND of its two components, so no
 * single-component signer, keygen or verifier is exported: with one in hand, a
 * caller could produce something shaped like a signature with no post-quantum
 * half. The helpers and wire identifiers below are exported because recomputing
 * a digest or recognizing an artifact needs exactly these bytes and names.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as sdk from "./index.js";

const surface = sdk as Record<string, unknown>;

test("no single signature component is exported", () => {
  for (const name of [
    "keygenMlDsa65",
    "signMlDsa65",
    "verifyMlDsa65",
    "generateEcdsaP256KeyPair",
    "signEcdsaP256Raw",
    "privateKeyFromPkcs8",
    "publicKeyB64FromPrivate",
  ]) {
    assert.ok(!(name in surface), `${name} must not be exported`);
  }
});

test("the helper set is exported", () => {
  for (const name of [
    "buildCollection",
    "resolveCollectionSubjects",
    "digestBytes",
    "digestHexBytes",
    "digestHexText",
    "jcsCanonicalizeBytes",
    "jcsCanonicalizeString",
    "computeExpiresAt",
    "deriveIssuerKey",
    "assembleContextSnapshotCertificate",
    "issuerKeyFingerprintHex",
    "buildAiDecisionPart",
    "buildAiDecisionSubject",
  ]) {
    assert.equal(typeof surface[name], "function", `${name} must be exported`);
  }
});

test("the wire identifiers are exported with their values", () => {
  assert.deepEqual(
    {
      ZERO_DATA_PROFILE: surface.ZERO_DATA_PROFILE,
      COMMITMENT_LEAF_VERSION: surface.COMMITMENT_LEAF_VERSION,
      PROFILE_P256_MLDSA65: surface.PROFILE_P256_MLDSA65,
      COLLECTION_MERKLE_SCHEME: surface.COLLECTION_MERKLE_SCHEME,
      SUBJECT_CONTEXT_SNAPSHOT: surface.SUBJECT_CONTEXT_SNAPSHOT,
    },
    {
      ZERO_DATA_PROFILE: "zero-data.unlinkable",
      COMMITMENT_LEAF_VERSION: "ccab1-commit",
      PROFILE_P256_MLDSA65: "certcrypt-composite-p256-mldsa65-v1",
      COLLECTION_MERKLE_SCHEME: "collection.merkle-sha3-256/1",
      SUBJECT_CONTEXT_SNAPSHOT: "subject.context-snapshot/1",
    }
  );
});

test("every implemented subject profile is listed as supported", () => {
  assert.deepEqual(sdk.SUPPORTED_SUBJECT_PROFILES, [
    "subject.binary/1",
    "subject.text/1",
    "subject.email/1",
    "subject.collection/1",
    "subject.ai-decision/1",
    "subject.context-snapshot/1",
  ]);
});
