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
 * SHA3-256 Merkle tree — issuer-side mirror of
 * `certcrypt-verifier-toolkit-js/core/crypto/merkle.ts`, ported byte-for-byte so
 * the SDK builds the exact same `holder_key_set_root` and inclusion proofs the
 * verifier checks.
 *
 * Construction (`holder-keyset.merkle-sha3-256/1`):
 * - leaf hash = SHA3-256(0x00 || leaf_preimage_bytes)
 * - node hash = SHA3-256(0x01 || left_bytes || right_bytes)
 * - odd-rightmost child promoted unchanged
 *
 * Field/byte order is load-bearing: a divergent byte breaks verification.
 */

import { digestHexBytes } from "./digest.js";

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/** Leaf hash: SHA3-256(0x00 || preimage_bytes), lowercase hex. */
export function computeLeafHash(preimageBytes: Uint8Array): string {
  const prefixed = new Uint8Array(1 + preimageBytes.length);
  prefixed.set(LEAF_PREFIX, 0);
  prefixed.set(preimageBytes, 1);
  return digestHexBytes(prefixed);
}

/** Internal node hash: SHA3-256(0x01 || left_bytes || right_bytes). */
function computeNodeHash(leftHex: string, rightHex: string): string {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const prefixed = new Uint8Array(1 + left.length + right.length);
  prefixed.set(NODE_PREFIX, 0);
  prefixed.set(left, 1);
  prefixed.set(right, 1 + left.length);
  return digestHexBytes(prefixed);
}

/**
 * Merkle root over leaf hashes. Odd-rightmost child promoted unchanged.
 * Single leaf: the root is that leaf hash.
 */
export function computeMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    throw new Error("cannot compute Merkle root of empty leaf set");
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  let level = [...leafHashes];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(computeNodeHash(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
  }
  return level[0];
}

/** Sibling hashes (inclusion proof) for a leaf, bottom-up. */
export function generateInclusionProof(
  leafHashes: string[],
  leafIndex: number
): string[] {
  if (leafHashes.length <= 1) return [];
  const siblings: string[] = [];
  let level = [...leafHashes];
  let idx = leafIndex;
  while (level.length > 1) {
    const hasSibling = idx % 2 === 1 || idx + 1 < level.length;
    if (hasSibling) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(level[siblingIdx]);
    }
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(computeNodeHash(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return siblings;
}

const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * Verify an inclusion proof against a root. Mirrors the verifier so the SDK can
 * self-check what it produced before shipping it.
 *
 * Fail-closed, never throws: `treeSize` must be a safe integer >= 1 and
 * `leafIndex` a safe integer in [0, treeSize); the leaf hash, the root and every
 * sibling must be 64-char lowercase hex; every sibling must be consumed.
 */
export function verifyInclusionProof(
  leafHash: string,
  leafIndex: number,
  siblingHashes: string[],
  expectedRoot: string,
  treeSize: number
): boolean {
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) return false;
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return false;
  if (typeof leafHash !== "string" || !HEX64_RE.test(leafHash)) return false;
  if (typeof expectedRoot !== "string" || !HEX64_RE.test(expectedRoot)) return false;
  if (!Array.isArray(siblingHashes)) return false;
  for (const s of siblingHashes) {
    if (typeof s !== "string" || !HEX64_RE.test(s)) return false;
  }

  let currentHash = leafHash;
  let currentIndex = leafIndex;
  let siblingIndex = 0;
  let levelWidth = treeSize;
  while (levelWidth > 1) {
    const isRight = currentIndex % 2 === 1;
    if (isRight || currentIndex + 1 < levelWidth) {
      if (siblingIndex >= siblingHashes.length) return false;
      const sibling = siblingHashes[siblingIndex++];
      currentHash = isRight
        ? computeNodeHash(sibling, currentHash)
        : computeNodeHash(currentHash, sibling);
    }
    currentIndex = Math.floor(currentIndex / 2);
    levelWidth = Math.ceil(levelWidth / 2);
  }
  return siblingIndex === siblingHashes.length && currentHash === expectedRoot;
}
