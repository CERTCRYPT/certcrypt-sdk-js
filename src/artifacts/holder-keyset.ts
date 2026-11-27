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
 * Holder operation-key tree (`holder-keyset.merkle-sha3-256/1`), issuer side.
 *
 * The holder commits to a Merkle root over a set of per-operation keys
 * (`holder_key_set_root`). The Level-2 authorization is signed (Level-1, by
 * CERTCRYPT) over that root **once**; thereafter the holder signs each projected
 * commitment with a DISTINCT, non-reused leaf key and discloses that leaf + its
 * inclusion proof. Two commitments from the same holder are therefore not
 * linkable BY KEY: no leaf repeats.
 *
 * They ARE linkable by root. `holder_key_set_root` is copied unprojected into
 * every `ProjectedAuthorization` (see `assembleEvidence` in capacity-evidence.ts,
 * which salts `holder_id`, `pool_id` and `authorization_id` through
 * `derivePseudonym` but passes the root through as-is), so any party holding two
 * artifacts can tell they share an issuer by comparing that one field. Unlinkability
 * is a key-mode property, not a property of the whole surface.
 *
 * Non-reuse is an emission invariant the verifier cannot enforce (it has no
 * global state); the holder (wallet) is responsible for never handing the same
 * `leaf_index` to two commitments. This module provides the keys and the
 * disclosure; the no-reuse bookkeeping lives in the wallet.
 *
 * Leaf hash = SHA3-256(0x00 || public_key_bytes). Root/proofs via the shared
 * SHA3-256 Merkle (`../crypto/merkle.js`), byte-identical to the
 * verifier.
 */

import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { keygenMlDsa65, signMlDsa65 } from "../crypto/ml-dsa.js";
import {
  computeLeafHash,
  computeMerkleRoot,
  generateInclusionProof,
} from "../crypto/merkle.js";

/** One per-operation signing keypair. Secret stays in holder custody. */
export interface OperationKey {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/**
 * The per-commitment object revealing one operation public key, its index, the
 * tree size and its inclusion proof. Field names match the wire shape the
 * verifier consumes (`OperationKeyDisclosure` in capacity-evidence).
 */
export interface OperationKeyDisclosure {
  leaf_index: number;
  public_key_b64: string;
  inclusion_proof: string[];
  tree_size: number;
}

/**
 * A holder key set: N operation keys, their leaf hashes, and the committed
 * Merkle root. Struct fields; `secretKey`s are sensitive and never
 * serialized.
 */
export class HolderKeySet {
  private readonly keys: OperationKey[];
  private readonly leafHashes: string[];
  /** `holder_key_set_root`: the value the Level-2 authorization commits to. */
  readonly root: string;

  private constructor(keys: OperationKey[]) {
    if (keys.length === 0) {
      throw new Error("holder key set must have at least one operation key");
    }
    this.keys = keys;
    this.leafHashes = keys.map((k) => computeLeafHash(k.publicKey));
    this.root = computeMerkleRoot(this.leafHashes);
  }

  /** Generate a fresh key set of `size` per-operation keys. */
  static generate(size: number): HolderKeySet {
    const keys: OperationKey[] = [];
    for (let i = 0; i < size; i++) {
      const { publicKey, secretKey } = keygenMlDsa65();
      keys.push({ publicKey, secretKey });
    }
    return new HolderKeySet(keys);
  }

  /**
   * Rebuild a key set from already-generated keys (e.g. restored from holder
   * custody). Recomputes leaves and root deterministically.
   */
  static fromKeys(keys: OperationKey[]): HolderKeySet {
    return new HolderKeySet(keys.map((k) => ({ ...k })));
  }

  /**
   * Derive the full operation-key tree DETERMINISTICALLY from one 32-byte master
   * seed — the canonical "seed + large tree" issuer custody model. The issuer
   * keeps only the 32-byte seed secret; the whole tree (and its `root`, the
   * `holder_key_set_root` the Level-1 authorization commits to) is reproducible
   * from it, so the same seed always yields the same root on any machine.
   *
   * Per-leaf seed = SHA3-256(masterSeed || utf8("op-key/<index>")). This is the
   * single canonical derivation: an issuer, the tooling,
   * and onboarding must all agree on the root, so it lives here in
   * the SDK rather than being re-implemented per integration.
   *
   * @param masterSeed 32-byte master seed (Uint8Array or 64-char hex string).
   * @param size       number of operation keys / leaves (e.g. 4096).
   */
  static fromMasterSeed(masterSeed: Uint8Array | string, size: number): HolderKeySet {
    const seed =
      typeof masterSeed === "string" ? Buffer.from(masterSeed, "hex") : Buffer.from(masterSeed);
    if (seed.length !== 32) {
      throw new Error("holder key set master seed must be 32 bytes (64 hex chars)");
    }
    if (!Number.isInteger(size) || size < 1) {
      throw new Error("holder key set size must be a positive integer");
    }
    const keys: OperationKey[] = [];
    for (let i = 0; i < size; i++) {
      const leafSeed = createHash("sha3-256")
        .update(seed)
        .update(Buffer.from(`op-key/${i}`, "utf8"))
        .digest();
      const { publicKey, secretKey } = keygenMlDsa65(leafSeed);
      keys.push({ publicKey, secretKey });
    }
    return new HolderKeySet(keys);
  }

  /**
   * Compute ONLY the `holder_key_set_root` for a master seed, without retaining
   * the derived keys — the value the issuer supplies at onboarding to
   * mint its Level-1 authorization. Convenience over `fromMasterSeed(...).root`.
   */
  static rootFromMasterSeed(masterSeed: Uint8Array | string, size: number): string {
    return HolderKeySet.fromMasterSeed(masterSeed, size).root;
  }

  get treeSize(): number {
    return this.keys.length;
  }

  /** The operation key at `leafIndex` (for signing exactly one commitment). */
  key(leafIndex: number): OperationKey {
    const k = this.keys[leafIndex];
    if (!k) {
      throw new Error(
        `leaf_index ${leafIndex} out of range (tree_size ${this.keys.length})`
      );
    }
    return k;
  }

  /** The inclusion-proof disclosure binding `leafIndex` to the root. */
  disclosure(leafIndex: number): OperationKeyDisclosure {
    const k = this.key(leafIndex);
    return {
      leaf_index: leafIndex,
      public_key_b64: Buffer.from(k.publicKey).toString("base64"),
      inclusion_proof: generateInclusionProof(this.leafHashes, leafIndex),
      tree_size: this.keys.length,
    };
  }

  /**
   * Sign `msg` with the leaf at `leafIndex`. The caller (wallet) is responsible
   * for never reusing a leaf — see the non-reuse invariant above.
   */
  sign(leafIndex: number, msg: Uint8Array): Uint8Array {
    return signMlDsa65(this.key(leafIndex).secretKey, msg);
  }
}
