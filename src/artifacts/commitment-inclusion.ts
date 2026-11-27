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
 * Commitment inclusion proof — the first level of the chained inclusion path
 * `commitment_id → subtree_root`.
 *
 * The verifier does NOT receive this artifact from the server/node — it is derived
 * client-side (issuer-side) from data already in `independence.proof/1`
 * (`consumed_commitment_ids` + `subtree_root`). This module lets the SDK assemble
 * it so the issuer can build a complete `verification-package/1`.
 *
 * BYTE-EXACTNESS MATTERS, and this is the one place it is easy to get wrong: the
 * leaf preimage is ordered-JSON `{v, commitment_id}` in INSERTION order, NOT
 * JCS/alphabetical. Every implementation emits `{"v":"…","commitment_id":"…"}`
 * with no spaces; canonicalizing alphabetically here would swap the two members
 * and every inclusion proof would fail to verify.
 */
import { computeLeafHash, computeMerkleRoot, generateInclusionProof } from "../crypto/merkle.js";

/** Version tag of the commitment sub-tree leaf preimage. */
export const COMMITMENT_LEAF_VERSION = "ccab1-commit";

/** The `CommitmentInclusionProof` shape a verifier consumes. */
export interface CommitmentInclusionProof {
  commitment_id: string;
  commitment_leaf_hash: string;
  commitment_index: string;
  commitment_siblings: string[];
  subtree_size: string;
}

/**
 * Ordered-JSON bytes preserving field insertion order (NOT alphabetical): the
 * verifier's `canonicalJsonBytes` and struct-ordered JSON
 * both produce `{"k":v,...}` with no whitespace. Kept private + minimal — only
 * strings are needed for the commitment leaf preimage.
 */
function orderedJsonBytes(orderedFields: [string, string][]): Uint8Array {
  const parts: string[] = ["{"];
  for (let i = 0; i < orderedFields.length; i++) {
    if (i > 0) parts.push(",");
    const [key, value] = orderedFields[i];
    parts.push(JSON.stringify(key) + ":" + JSON.stringify(value));
  }
  parts.push("}");
  return new TextEncoder().encode(parts.join(""));
}

/** Commitment leaf hash: SHA3-256(0x00 || orderedJson({v, commitment_id})). */
export function commitmentLeafHash(commitmentId: string): string {
  return computeLeafHash(
    orderedJsonBytes([
      ["v", COMMITMENT_LEAF_VERSION],
      ["commitment_id", commitmentId],
    ])
  );
}

/**
 * Build the `commitment → subtree_root` inclusion proof for the commitment at
 * `commitmentIndex` among the leaf's accepted `commitmentIds` (their canonical
 * leaf order = `independence.proof/1.consumed_commitment_ids`). The result
 * self-verifies against `subtree_root` from the same inputs.
 *
 * Throws on an empty set (a settlement leaf must carry ≥1 accepted commitment;) or an out-of-range index.
 */
export function buildCommitmentInclusionProof(
  commitmentIds: string[],
  commitmentIndex: number
): CommitmentInclusionProof {
  if (commitmentIds.length === 0) {
    throw new Error("commitment inclusion proof requires at least one commitment id");
  }
  if (commitmentIndex < 0 || commitmentIndex >= commitmentIds.length) {
    throw new Error(
      `commitmentIndex ${commitmentIndex} out of range (${commitmentIds.length} commitments)`
    );
  }
  const leafHashes = commitmentIds.map(commitmentLeafHash);
  // computeMerkleRoot is not needed for the proof itself (the verifier derives
  // the root from the siblings), but computing it here would let a caller assert
  // it equals the proof's subtree_root; we keep the builder minimal.
  const siblings = generateInclusionProof(leafHashes, commitmentIndex);
  return {
    commitment_id: commitmentIds[commitmentIndex],
    commitment_leaf_hash: leafHashes[commitmentIndex],
    commitment_index: String(commitmentIndex),
    commitment_siblings: siblings,
    subtree_size: String(leafHashes.length),
  };
}

/** Subtree root over the accepted commitments (for an optional self-check). */
export function commitmentSubtreeRoot(commitmentIds: string[]): string {
  if (commitmentIds.length === 0) {
    throw new Error("subtree root requires at least one commitment id");
  }
  return computeMerkleRoot(commitmentIds.map(commitmentLeafHash));
}
