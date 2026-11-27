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

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { siblingPath, missingSibling } from "../test-support/siblings.js";

import { Buffer } from "node:buffer";

import {
  computeLeafHash,
  computeMerkleRoot,
  generateInclusionProof,
  verifyInclusionProof,
} from "../crypto/merkle.js";
import { HolderKeySet } from "./holder-keyset.js";
import { verifyMlDsa65, keygenMlDsa65 } from "../crypto/ml-dsa.js";

const FIXTURE = ["fixtures", "primitives", "holder-keyset", "vectors.json"];
const VECTORS_PATH = siblingPath(import.meta.url, "certcrypt-conformance", ...FIXTURE);
const skip = missingSibling(import.meta.url, "certcrypt-conformance", ...FIXTURE);

interface KeysetVectors {
  tree_size: number;
  leaves: { leaf_index: number; public_key_bytes_hex: string; expected_leaf_hash: string }[];
  expected_root: string;
  inclusion_proofs: { leaf_index: number; sibling_hashes: string[] }[];
}

function loadVectors(): KeysetVectors {
  return JSON.parse(readFileSync(VECTORS_PATH, "utf-8")) as KeysetVectors;
}

function hexToBytes(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return b;
}

// --- Conformance parity: the Merkle layer reproduces the pinned vectors -----

test("CONFORMANCE: leaf hashes match holder-keyset vectors byte-for-byte", {skip}, () => {
  const v = loadVectors();
  for (const leaf of v.leaves) {
    const got = computeLeafHash(hexToBytes(leaf.public_key_bytes_hex));
    assert.equal(
      got,
      leaf.expected_leaf_hash,
      `leaf ${leaf.leaf_index}: leaf hash diverged from conformance vector`
    );
  }
});

test("CONFORMANCE: Merkle root matches holder-keyset vector", {skip}, () => {
  const v = loadVectors();
  const leafHashes = v.leaves.map((l) => computeLeafHash(hexToBytes(l.public_key_bytes_hex)));
  assert.equal(computeMerkleRoot(leafHashes), v.expected_root, "root diverged");
});

test("CONFORMANCE: generated inclusion proofs match the pinned proofs", {skip}, () => {
  const v = loadVectors();
  const leafHashes = v.leaves.map((l) => computeLeafHash(hexToBytes(l.public_key_bytes_hex)));
  for (const proof of v.inclusion_proofs) {
    const got = generateInclusionProof(leafHashes, proof.leaf_index);
    assert.deepEqual(
      got,
      proof.sibling_hashes,
      `leaf ${proof.leaf_index}: inclusion proof diverged`
    );
  }
});

test("CONFORMANCE: each pinned proof verifies against the expected root", {skip}, () => {
  const v = loadVectors();
  for (const leaf of v.leaves) {
    const leafHash = computeLeafHash(hexToBytes(leaf.public_key_bytes_hex));
    const proof = v.inclusion_proofs.find((p) => p.leaf_index === leaf.leaf_index)!;
    assert.ok(
      verifyInclusionProof(leafHash, leaf.leaf_index, proof.sibling_hashes, v.expected_root, v.tree_size),
      `leaf ${leaf.leaf_index}: pinned proof failed verification`
    );
  }
});

test("CONFORMANCE: a leaf not in the tree fails membership (must_hold)", {skip}, () => {
  const v = loadVectors();
  const foreignLeaf = computeLeafHash(new Uint8Array(32).fill(0xff));
  const proof = v.inclusion_proofs[0];
  assert.equal(
    verifyInclusionProof(foreignLeaf, 0, proof.sibling_hashes, v.expected_root, v.tree_size),
    false,
    "a foreign leaf must NOT verify against the authorized root"
  );
});

// --- HolderKeySet end-to-end: generate, disclose, sign, self-verify --------

test("HolderKeySet: generated tree is internally consistent (root over its leaves)", () => {
  const ks = HolderKeySet.generate(4);
  assert.equal(ks.treeSize, 4);
  // Each disclosure's proof verifies against the set's own root.
  for (let i = 0; i < 4; i++) {
    const d = ks.disclosure(i);
    const leafHash = computeLeafHash(new Uint8Array(Buffer.from(d.public_key_b64, "base64")));
    assert.ok(
      verifyInclusionProof(leafHash, d.leaf_index, d.inclusion_proof, ks.root, d.tree_size),
      `leaf ${i}: disclosure does not verify against the set root`
    );
  }
});

test("HolderKeySet: a leaf signature verifies against the disclosed leaf key", () => {
  const ks = HolderKeySet.generate(3);
  const msg = new TextEncoder().encode("commitment-signing-bytes-placeholder");
  const sig = ks.sign(1, msg);
  const d = ks.disclosure(1);
  const leafPk = new Uint8Array(Buffer.from(d.public_key_b64, "base64"));
  assert.ok(verifyMlDsa65(leafPk, msg, sig), "leaf signature must verify against its public key");
});

test("HolderKeySet: distinct leaves expose distinct keys (unlinkability by key)", () => {
  const ks = HolderKeySet.generate(4);
  const a = ks.disclosure(0).public_key_b64;
  const b = ks.disclosure(1).public_key_b64;
  assert.notEqual(a, b, "two leaves must not share a public key");
});

test("HolderKeySet: single-leaf tree — root is the leaf hash, empty proof", () => {
  const ks = HolderKeySet.generate(1);
  const d = ks.disclosure(0);
  const leafHash = computeLeafHash(new Uint8Array(Buffer.from(d.public_key_b64, "base64")));
  assert.equal(ks.root, leafHash, "single-leaf root must equal the leaf hash");
  assert.deepEqual(d.inclusion_proof, [], "single-leaf inclusion proof must be empty");
  assert.ok(verifyInclusionProof(leafHash, 0, [], ks.root, 1), "single-leaf proof verifies");
});

test("HolderKeySet: out-of-range leaf_index throws", () => {
  const ks = HolderKeySet.generate(2);
  assert.throws(() => ks.key(5), /out of range/);
});

test("HolderKeySet: fromKeys rebuilds the same root", () => {
  const a = keygenMlDsa65();
  const b = keygenMlDsa65();
  const ks1 = HolderKeySet.fromKeys([a, b].map((k) => ({ publicKey: k.publicKey, secretKey: k.secretKey })));
  const ks2 = HolderKeySet.fromKeys([a, b].map((k) => ({ publicKey: k.publicKey, secretKey: k.secretKey })));
  assert.equal(ks1.root, ks2.root, "same keys must yield the same root");
});

test("verifyInclusionProof fails closed on shape (bounds, integers, hex)", () => {
  const leaves = [0, 1, 2, 3].map((k) => computeLeafHash(new Uint8Array(32).fill(k)));
  const root = computeMerkleRoot(leaves);
  const proof = generateInclusionProof(leaves, 0);
  assert.equal(verifyInclusionProof(leaves[0], 0, proof, root, 4), true);
  assert.equal(verifyInclusionProof(leaves[3], 4, generateInclusionProof(leaves, 3), root, 4), false);
  assert.equal(verifyInclusionProof(leaves[0], 0, proof, root, 0), false);
  assert.equal(verifyInclusionProof(leaves[0], 0.5, proof, root, 4), false);
  assert.equal(verifyInclusionProof(leaves[0], 0, [proof[0].toUpperCase(), proof[1]], root, 4), false);
  assert.equal(verifyInclusionProof(leaves[0], 0, ["zz".repeat(32), proof[1]], root, 4), false);
  assert.equal(verifyInclusionProof(leaves[0], 0, proof.slice(0, 1), root, 4), false);
});
