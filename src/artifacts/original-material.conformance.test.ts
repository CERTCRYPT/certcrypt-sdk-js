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
 * Subject commitments and the submission-set id, against the contract.
 *
 * Both are things this SDK COMPUTES and a verifier later recomputes from the
 * material it is given. If they diverge, a certificate this SDK mints resolves to
 * a commitment nobody can reproduce — and this SDK notices nothing, because it
 * never recomputes its own output.
 *
 * The commitment construction is deliberately the ASCII concatenation of two hex
 * STRINGS, not of the binary digests they denote. That is the mistake the
 * contract calls out by name, and it is easy to make: the hex is right there and
 * the bytes feel more natural to hash.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { computeSubjectCommitment } from "./base-certificate.js";
import { digestHexBytes } from "../crypto/digest.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { siblingPath } from "../test-support/siblings.js";

function familyDir(family: string): string {
  return siblingPath(
    import.meta.url,
    "certcrypt-conformance",
    "fixtures",
    "primitives",
    family
  );
}

function vectors(family: string): any | null {
  const path = join(familyDir(family), "vectors.json");
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

test("subject commitments match the contract", () => {
  const v = vectors("original-material");
  if (v === null) return; // the sibling guard reports absence, loudly

  for (const s of v.subjects) {
    const got = computeSubjectCommitment(
      v.nonce_hex,
      s.expected_subject_local_digest_hex
    );
    assert.equal(
      got,
      s.expected_commitment_digest_hex,
      `subject ${s.index} (${s.profile}): commitment diverged — the construction is ` +
        `SHA3-256 over the ASCII of the two hex strings, not over the bytes they denote`
    );
  }
});

test("hashing the raw digest bytes yields a different commitment", () => {
  // The named mistake, reproduced so the distinction is pinned rather than
  // asserted in prose: if these ever coincided, the test above would stop
  // discriminating between the right construction and the wrong one.
  const v = vectors("original-material");
  if (v === null) return;

  const s = v.subjects[0];
  const rawConcat = Buffer.concat([
    Buffer.from(v.nonce_hex, "hex"),
    Buffer.from(s.expected_subject_local_digest_hex, "hex"),
  ]);
  assert.notEqual(
    digestHexBytes(new Uint8Array(rawConcat)),
    s.expected_commitment_digest_hex,
    "hashing the raw bytes must NOT produce the contract's commitment"
  );
});

test("the submission-set id recomputes to the contract's value", () => {
  const v = vectors("submission-set");
  if (v === null) return;

  const artifactPath = join(familyDir("submission-set"), v.submission_set_artifact_path);
  if (!existsSync(artifactPath)) return;
  const set = JSON.parse(readFileSync(artifactPath, "utf-8"));

  // The id is the digest of the set with the id field REMOVED — a set cannot
  // commit to a value derived from itself.
  const { submission_set_id: _omit, ...noId } = set;
  assert.equal(
    digestHexBytes(jcsCanonicalizeBytes(noId)),
    v.expected_submission_set_id,
    "submission_set_id diverged — the no-id view, or JCS vs insertion order"
  );

  // And the artifact's own embedded id must agree with the recompute, or the
  // fixture is internally inconsistent.
  if (typeof set.submission_set_id === "string") {
    assert.equal(
      set.submission_set_id,
      v.expected_submission_set_id,
      "the fixture's embedded id disagrees with its own expected value"
    );
  }
});
