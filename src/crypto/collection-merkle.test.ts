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
 * Parity of the SDK's `collection.merkle-sha3-256/1` port against the shared
 * conformance vectors.
 *
 * This is what makes porting the scheme (rather than depending on the toolkit)
 * safe: issuer and verifier are pinned to the same vectors, so a one-byte
 * divergence fails here instead of surfacing as an unverifiable certificate in
 * production. Fails when the conformance repo is not a sibling checkout (see
 * `test-support/siblings.ts`).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { siblingPath, missingSibling } from "../test-support/siblings.js";
import {
  collectionLeafHash,
  collectionMerkleRoot,
  collectionInclusionProof,
  buildCollection,
  COLLECTION_MERKLE_SCHEME
} from "./collection-merkle.js";

const VECTORS = siblingPath(
  import.meta.url,
  "certcrypt-conformance",
  "fixtures",
  "primitives",
  "collection-merkle"
);
const skip = missingSibling(
  import.meta.url,
  "certcrypt-conformance",
  "fixtures",
  "primitives",
  "collection-merkle"
);

interface Vector {
  label: string;
  commitment_scheme: string;
  collection_salt_hex: string;
  leaf_profile: string;
  declared_cardinality: string;
  leaves_hex: string[];
  root: string;
  inclusion_proofs: { proof_version: string; leaf_index: string; sibling_hashes: string[] }[];
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return out;
}

function loadVectors(): Vector[] {
  return readdirSync(VECTORS)
    .filter((f) => f.startsWith("vector-") && f.endsWith(".json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(VECTORS, f), "utf-8")) as Vector);
}

test("collection-merkle: roots reproduce the conformance vectors", { skip }, () => {
  const vectors = loadVectors();
  assert.ok(vectors.length >= 6, `expected >= 6 vectors, found ${vectors.length}`);
  for (const v of vectors) {
    assert.equal(v.commitment_scheme, COLLECTION_MERKLE_SCHEME, `${v.label}: scheme`);
    const salt = hexToBytes(v.collection_salt_hex);
    const leafHashes = v.leaves_hex.map((h) =>
      collectionLeafHash(salt, v.leaf_profile, hexToBytes(h))
    );
    assert.equal(collectionMerkleRoot(leafHashes), v.root, `${v.label}: root`);
    assert.equal(String(leafHashes.length), v.declared_cardinality, `${v.label}: cardinality`);
  }
});

test("collection-merkle: inclusion paths reproduce the vectors", { skip }, () => {
  for (const v of loadVectors()) {
    const salt = hexToBytes(v.collection_salt_hex);
    const leafHashes = v.leaves_hex.map((h) =>
      collectionLeafHash(salt, v.leaf_profile, hexToBytes(h))
    );
    for (const ip of v.inclusion_proofs) {
      const got = collectionInclusionProof(leafHashes, Number(ip.leaf_index));
      assert.deepEqual(got, ip.sibling_hashes, `${v.label}: proof[${ip.leaf_index}]`);
    }
  }
});

test("collection-merkle: the salt changes the root", { skip }, () => {
  const v = loadVectors()[0];
  const leaves = v.leaves_hex.map(hexToBytes);
  const a = leaves.map((b) => collectionLeafHash(hexToBytes(v.collection_salt_hex), v.leaf_profile, b));
  const other = new TextEncoder().encode("a different salt entirely");
  const b = leaves.map((x) => collectionLeafHash(other, v.leaf_profile, x));
  assert.notEqual(
    collectionMerkleRoot(a),
    collectionMerkleRoot(b),
    "the same leaves under a different salt must not share a root"
  );
});

test("collection-merkle: an empty salt is rejected", { skip }, () => {
  assert.throws(
    () => collectionLeafHash(new Uint8Array(0), "subject.binary/1", new Uint8Array([1])),
    /non-empty collection salt/,
    "an empty salt must throw rather than fall back to the unsalted construction"
  );
});

test("collection-merkle: buildCollection produces a descriptor the verifier can check", { skip }, () => {
  const salt = new TextEncoder().encode("f".repeat(64));
  const leaves = ["one", "two", "three", "four", "five"].map((s) =>
    new TextEncoder().encode(s)
  );
  const built = buildCollection(
    salt,
    leaves.map((bytes) => ({ profile: "subject.binary/1", bytes }))
  );
  assert.equal(built.descriptor.declared_cardinality, "5");
  assert.equal(built.leafHashes.length, 5);
  // The descriptor's root MUST be the fold of the leaf hashes it ships with.
  assert.equal(collectionMerkleRoot(built.leafHashes), built.descriptor.root);
  // Exactly the four members the profile allows, no more.
  assert.deepEqual(Object.keys(built.descriptor).sort(), [
    "commitment_scheme",
    "declared_cardinality",
    "leaves",
    "root"
  ]);
  // Every leaf declares its own profile and its own commitment, in leaf order.
  assert.deepEqual(
    built.descriptor.leaves.map((l) => l.commitment_digest_hex),
    built.leafHashes
  );
});

test("collection-merkle: a heterogeneous collection mixes profiles per leaf", { skip }, () => {
  const salt = new TextEncoder().encode("e".repeat(64));
  const enc = new TextEncoder();
  // The point of `leaves[]`: text and binary in ONE collection, one cardinality.
  const built = buildCollection(salt, [
    { profile: "subject.text/1", bytes: enc.encode("line one\nline two") },
    { profile: "subject.binary/1", bytes: new Uint8Array([0, 1, 2, 255]) },
    { profile: "subject.text/1", bytes: enc.encode("third") }
  ]);
  assert.deepEqual(built.descriptor.leaves.map((l) => l.profile), [
    "subject.text/1",
    "subject.binary/1",
    "subject.text/1"
  ]);
  assert.equal(built.descriptor.declared_cardinality, "3");
  assert.equal(collectionMerkleRoot(built.leafHashes), built.descriptor.root);
  // The profile enters the leaf preimage, so re-declaring the same bytes under a
  // different profile MUST move the root — that is why it travels signed.
  const relabelled = buildCollection(salt, [
    { profile: "subject.binary/1", bytes: enc.encode("line one\nline two") },
    { profile: "subject.binary/1", bytes: new Uint8Array([0, 1, 2, 255]) },
    { profile: "subject.text/1", bytes: enc.encode("third") }
  ]);
  assert.notEqual(built.descriptor.root, relabelled.descriptor.root);
});
