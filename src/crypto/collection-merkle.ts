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
 * `collection.merkle-sha3-256/1` — issuer-side mirror of
 * `certcrypt-verifier-toolkit-js/core/crypto/collection-merkle.ts`, ported
 * byte-for-byte so the SDK builds the exact same root and leaf hashes the verifier
 * recomputes. Pinned against the shared conformance vectors
 * (`collection-merkle.test.ts`): a one-byte divergence fails that test.
 *
 * DISTINCT from `merkle.ts` in this same directory, which implements
 * `holder-keyset.merkle-sha3-256/1` (0x00/0x01 prefixes, no salt, different
 * preimage). The two are not interchangeable and produce different roots.
 *
 * Construction:
 *   leaf_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:leaf")
 *     || u64be(len(collection_salt)) || collection_salt
 *     || u64be(len(leaf_profile))    || leaf_profile
 *     || u64be(len(leaf_canonical))  || leaf_canonical
 *   node_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:node") || L || R
 *   root: one leaf → its own hash; else pair left-to-right and promote a lone
 *   right-edge hash unchanged until one remains. Empty tree is invalid.
 *
 * The salt is what makes a collection root operation-specific: under
 * `subject.collection/1` §8 it is the certificate anchor's `nonce_hex` as ASCII
 * bytes, so the same leaf set yields a different root in every operation. That is
 * the property that lets leaf hashes travel in a `verification_package` without
 * becoming stable global identifiers of content.
 */

import { digestHexBytes } from "./digest.js";
import { canonicalBytesForSubject } from "./canonical-subject.js";

export const COLLECTION_MERKLE_SCHEME = "collection.merkle-sha3-256/1";

const LEAF_TAG = new TextEncoder().encode(
  "CERTCRYPT:collection.merkle-sha3-256/1:leaf"
);
const NODE_TAG = new TextEncoder().encode(
  "CERTCRYPT:collection.merkle-sha3-256/1:node"
);

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex length must be even");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return out;
}

/**
 * `leaf_hash` for one leaf, given the collection salt, the declared `leaf_profile`
 * and the leaf's `canonical_bytes`. Lowercase hex.
 *
 * An empty salt throws: the scheme requires one, and accepting none would silently
 * reproduce the unsalted construction.
 */
export function collectionLeafHash(
  collectionSalt: Uint8Array,
  leafProfile: string,
  leafCanonicalBytes: Uint8Array
): string {
  if (collectionSalt.length === 0) {
    throw new Error(
      "collection.merkle-sha3-256/1: a non-empty collection salt is required"
    );
  }
  const profileBytes = new TextEncoder().encode(leafProfile);
  return digestHexBytes(
    concat(
      LEAF_TAG,
      u64be(collectionSalt.length),
      collectionSalt,
      u64be(profileBytes.length),
      profileBytes,
      u64be(leafCanonicalBytes.length),
      leafCanonicalBytes
    )
  );
}

/** `node_hash` for two child hashes (lowercase hex in, lowercase hex out). */
export function collectionNodeHash(leftHex: string, rightHex: string): string {
  return digestHexBytes(concat(NODE_TAG, hexToBytes(leftHex), hexToBytes(rightHex)));
}

/** One fold step: pair left-to-right, promote a lone right edge unchanged. */
function foldOnce(level: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < level.length; i += 2) {
    out.push(i + 1 < level.length ? collectionNodeHash(level[i], level[i + 1]) : level[i]);
  }
  return out;
}

/** The collection root over an ordered list of leaf hashes. */
export function collectionMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    throw new Error("collection.merkle-sha3-256/1: empty tree is invalid");
  }
  let level = leafHashes;
  while (level.length > 1) level = foldOnce(level);
  return level[0];
}

/**
 * Sibling path for one leaf, bottom-up.
 *
 * A node that is the lone right edge of an odd level is promoted unchanged and
 * therefore contributes NO sibling — the case a careless implementation gets wrong,
 * and the reason the conformance vectors include odd cardinalities.
 */
export function collectionInclusionProof(
  leafHashes: string[],
  leafIndex: number
): string[] {
  if (leafIndex < 0 || leafIndex >= leafHashes.length) {
    throw new Error(`leaf index ${leafIndex} out of range`);
  }
  const siblings: string[] = [];
  let level = leafHashes;
  let idx = leafIndex;
  while (level.length > 1) {
    const lone = idx === level.length - 1 && level.length % 2 === 1;
    if (!lone) siblings.push(idx % 2 === 0 ? level[idx + 1] : level[idx - 1]);
    level = foldOnce(level);
    idx = Math.floor(idx / 2);
  }
  return siblings;
}

/** One leaf as the signed descriptor declares it: its own profile and commitment. */
export interface CollectionLeafEntry {
  profile: string;
  commitment_digest_hex: string;
}

/** A built collection: the descriptor the certificate commits to, plus its leaf hashes. */
export interface BuiltCollection {
  /** The four-member descriptor, ready to be canonicalized as the subject value. */
  descriptor: {
    commitment_scheme: string;
    root: string;
    declared_cardinality: string;
    leaves: CollectionLeafEntry[];
  };
  /** Leaf hashes in leaf order — the same values `descriptor.leaves[].commitment_digest_hex` carries. */
  leafHashes: string[];
}

/** One leaf's input: the profile it is declared under and its raw bytes. */
export interface CollectionLeafInput {
  profile: string;
  bytes: Uint8Array;
}

/**
 * Build a collection subject from its ordered leaves.
 *
 * This is the operation an issuer cannot do before emitting: the salt is the
 * certificate's own nonce, so the root is only computable once that nonce exists.
 * The SDK therefore builds the collection during `prepare()` (and so `issue()`),
 * not before it.
 *
 * Each leaf carries its OWN profile — a collection may mix texts, binaries and
 * emails (`subject.collection/1` §7.4). Every leaf is canonicalized under its own
 * profile before hashing, exactly as the verifier does when it recomputes the root
 * from delivered material; that is why the profile must travel signed inside the
 * descriptor rather than alongside it.
 */
export function buildCollection(
  collectionSalt: Uint8Array,
  leaves: CollectionLeafInput[]
): BuiltCollection {
  if (leaves.length === 0) {
    throw new Error("subject.collection/1: a collection needs at least one leaf");
  }
  const leafHashes = leaves.map((leaf) =>
    collectionLeafHash(
      collectionSalt,
      leaf.profile,
      canonicalBytesForSubject(leaf.profile, leaf.bytes)
    )
  );
  return {
    descriptor: {
      commitment_scheme: COLLECTION_MERKLE_SCHEME,
      root: collectionMerkleRoot(leafHashes),
      declared_cardinality: String(leaves.length),
      leaves: leaves.map((leaf, i) => ({
        profile: leaf.profile,
        commitment_digest_hex: leafHashes[i]
      }))
    },
    leafHashes
  };
}
