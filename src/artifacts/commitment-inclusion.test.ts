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
 * `commitment_id → subtree_root` inclusion proofs.
 *
 * This is public surface (`buildCommitmentInclusionProof`, `commitmentLeafHash`,
 * `commitmentSubtreeRoot`) that a verifier recomputes independently, so the tests
 * assert PROPERTIES rather than restating the implementation:
 *
 *   - every proof the builder emits folds back to the subtree root, checked with
 *     `verifyInclusionProof` (the same fold a verifier runs);
 *   - the leaf preimage is ordered JSON `{v, commitment_id}` in INSERTION order,
 *     not JCS/alphabetical — the module's own doc calls this the one place that is
 *     easy to get wrong, and swapping the two members silently breaks every proof;
 *   - the failure modes fail closed rather than emitting a proof that cannot verify.
 *
 * Odd cardinalities are covered on purpose: a lone right-edge node is promoted
 * unchanged and contributes no sibling, which is where a fold implementation
 * usually breaks. The 1..9 sweep is chosen to hit every parity combination in the
 * first few levels — it is NOT a supported maximum: the builder has no cap, and a
 * separate case pins large, deep trees.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildCommitmentInclusionProof,
  commitmentLeafHash,
  commitmentSubtreeRoot,
  COMMITMENT_LEAF_VERSION,
} from "./commitment-inclusion.js";
import { computeLeafHash, verifyInclusionProof } from "../crypto/merkle.js";
import { digestHexBytes } from "../crypto/digest.js";

/** Deterministic 64-hex commitment ids — the shape the settlement leaf carries. */
function ids(n: number): string[] {
  return Array.from({ length: n }, (_, i) => String(i + 1).padStart(2, "0").repeat(32));
}

test("every proof folds back to the subtree root, for every index and cardinality", () => {
  // 1..9 covers both parities at every level, including the lone-right-edge case
  // an odd level promotes unchanged.
  for (let size = 1; size <= 9; size++) {
    const commitmentIds = ids(size);
    const root = commitmentSubtreeRoot(commitmentIds);
    for (let index = 0; index < size; index++) {
      const proof = buildCommitmentInclusionProof(commitmentIds, index);
      assert.equal(proof.commitment_id, commitmentIds[index]);
      assert.equal(proof.commitment_index, String(index));
      assert.equal(proof.subtree_size, String(size));
      assert.ok(
        verifyInclusionProof(
          proof.commitment_leaf_hash,
          index,
          proof.commitment_siblings,
          root,
          size
        ),
        `size=${size} index=${index}: the proof must fold to the subtree root`
      );
    }
  }
});

test("cardinality is not bounded by the builder: a realistic settlement leaf folds too", () => {
  // The 1..9 sweep above pins the PARITY cases (a lone right edge promoted
  // unchanged) at every level, which is where a fold breaks. It is not a limit:
  // this builder has no cap of its own. A settlement leaf aggregates whatever a
  // window consumed, so it routinely exceeds the 64-member bound on a single
  // SUBMISSION SET — a different thing entirely. Pin a large, deep tree (and its
  // odd neighbor, so the last level is uneven) rather than sweeping thousands.
  for (const size of [64, 65, 257]) {
    const commitmentIds = ids(size);
    const root = commitmentSubtreeRoot(commitmentIds);
    // Endpoints plus the middle: first, last (the lone-right-edge candidate) and
    // an interior index. Sweeping every index here would only repeat the shapes
    // the 1..9 case already covers, at a much higher cost.
    for (const index of [0, size >> 1, size - 1]) {
      const proof = buildCommitmentInclusionProof(commitmentIds, index);
      assert.ok(
        verifyInclusionProof(
          proof.commitment_leaf_hash,
          index,
          proof.commitment_siblings,
          root,
          size
        ),
        `size=${size} index=${index}: the proof must fold to the subtree root`
      );
    }
  }
});

test("a proof does NOT verify against another commitment's root", () => {
  // Guards the direction that matters: a proof is evidence about ONE commitment,
  // so it must not validate against a set it does not belong to.
  const a = ids(5);
  const b = a.slice();
  b[4] = "ff".repeat(32); // one different member → a different root
  const proof = buildCommitmentInclusionProof(a, 2);
  assert.ok(
    verifyInclusionProof(proof.commitment_leaf_hash, 2, proof.commitment_siblings, commitmentSubtreeRoot(a), 5)
  );
  assert.ok(
    !verifyInclusionProof(proof.commitment_leaf_hash, 2, proof.commitment_siblings, commitmentSubtreeRoot(b), 5),
    "a proof must not verify against a root it was not built from"
  );
});

test("the leaf preimage is ordered JSON {v, commitment_id} — insertion order, not JCS", () => {
  // The trap this module documents. Alphabetical canonicalization would emit
  // {"commitment_id":…,"v":…} and every proof would fail to verify against a
  // conforming verifier. Pin the exact preimage bytes, independently derived.
  const commitmentId = "ab".repeat(32);
  const expectedPreimage = `{"v":"${COMMITMENT_LEAF_VERSION}","commitment_id":"${commitmentId}"}`;
  const expected = computeLeafHash(new TextEncoder().encode(expectedPreimage));
  assert.equal(commitmentLeafHash(commitmentId), expected);

  // And the alphabetical form must NOT match — otherwise this test would pass
  // even if the builder had been "fixed" to canonicalize by key.
  const jcsPreimage = `{"commitment_id":"${commitmentId}","v":"${COMMITMENT_LEAF_VERSION}"}`;
  assert.notEqual(
    commitmentLeafHash(commitmentId),
    computeLeafHash(new TextEncoder().encode(jcsPreimage)),
    "JCS/alphabetical member order must not produce the same leaf hash"
  );
});

test("the leaf hash is domain-separated from a bare digest of the preimage", () => {
  // computeLeafHash prefixes 0x00, so a leaf can never collide with an internal
  // node (0x01) or with an unprefixed hash of the same bytes.
  const commitmentId = "cd".repeat(32);
  const preimage = `{"v":"${COMMITMENT_LEAF_VERSION}","commitment_id":"${commitmentId}"}`;
  assert.notEqual(
    commitmentLeafHash(commitmentId),
    digestHexBytes(new TextEncoder().encode(preimage)),
    "the leaf hash must be domain-separated, not a bare digest"
  );
  assert.match(commitmentLeafHash(commitmentId), /^[0-9a-f]{64}$/);
});

test("distinct commitment ids give distinct leaves; the same id is deterministic", () => {
  const [a, b] = ids(2);
  assert.notEqual(commitmentLeafHash(a), commitmentLeafHash(b));
  assert.equal(commitmentLeafHash(a), commitmentLeafHash(a));
});

test("a single-commitment set: the leaf IS the root, with no siblings", () => {
  const commitmentIds = ids(1);
  const proof = buildCommitmentInclusionProof(commitmentIds, 0);
  assert.deepEqual(proof.commitment_siblings, []);
  assert.equal(proof.commitment_leaf_hash, commitmentSubtreeRoot(commitmentIds));
  assert.equal(proof.subtree_size, "1");
});

test("member order is load-bearing: reordering the set changes the root", () => {
  // consumed_commitment_ids is a canonical ORDER, not a set — the proof positions
  // the commitment by index, so a reorder must not silently still verify.
  const commitmentIds = ids(4);
  const swapped = [commitmentIds[1], commitmentIds[0], commitmentIds[2], commitmentIds[3]];
  assert.notEqual(commitmentSubtreeRoot(commitmentIds), commitmentSubtreeRoot(swapped));
});

// --- fail-closed -----------------------------------------------------------
// A builder that returned something unusable would surface as an unverifiable
// package in a third party's hands, long after issuance. It throws instead.

test("an empty commitment set is refused, not silently rooted", () => {
  assert.throws(() => buildCommitmentInclusionProof([], 0), /at least one commitment id/);
  assert.throws(() => commitmentSubtreeRoot([]), /at least one commitment id/);
});

test("an out-of-range index is refused", () => {
  const commitmentIds = ids(3);
  assert.throws(() => buildCommitmentInclusionProof(commitmentIds, 3), /out of range/);
  assert.throws(() => buildCommitmentInclusionProof(commitmentIds, -1), /out of range/);
});
