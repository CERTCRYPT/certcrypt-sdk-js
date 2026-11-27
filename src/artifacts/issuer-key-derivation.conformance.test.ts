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
 * The issuer's signing key, from its seed alone, against the contract.
 *
 * Conformance family `issuer-key-derivation`. A divergence here produces
 * certificates that still verify, each carrying its own public keys, while one
 * seed signs under two identities. Nothing downstream notices, so the contract is
 * read here: the two public keys, the default key id per tree size, and the key
 * id being a label that never changes the key.
 */

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";

import { Certcrypt } from "../issuer.js";
import { deriveIssuerKey, type IssuerKey } from "./base-certificate.js";
import { HolderKeySet } from "./holder-keyset.js";
import { missingSibling, siblingPath } from "../test-support/siblings.js";

const FIXTURE = ["fixtures", "primitives", "issuer-key-derivation", "vectors.json"];
const skip = missingSibling(import.meta.url, "certcrypt-conformance", ...FIXTURE);

function doc(): any {
  return JSON.parse(
    readFileSync(siblingPath(import.meta.url, "certcrypt-conformance", ...FIXTURE), "utf-8")
  );
}

/** The key `issue()` signs under, read off an issuer configured like an integration. */
function issuerKeyOf(opts: { seedHex: string; treeSize?: number; issuerKeyId?: string }): IssuerKey {
  const issuer = new Certcrypt({
    nodeBaseUrl: "http://node.invalid",
    keysetSeed: opts.seedHex,
    rulesVersion: "rules/conformance",
    systemRootFingerprint: "aa".repeat(32),
    systemId: "certcrypt",
    ...(opts.treeSize !== undefined ? { treeSize: opts.treeSize } : {}),
    ...(opts.issuerKeyId !== undefined ? { issuerKeyId: opts.issuerKeyId } : {}),
  });
  return (issuer as unknown as { resolveIssuerKey(): IssuerKey }).resolveIssuerKey();
}

test("the profile is the one this SDK implements", { skip }, () => {
  assert.equal(doc().profile, "issuer-key-derivation/1");
});

test("the seed derives the contract's two public keys", { skip }, () => {
  for (const v of doc().vectors) {
    const key = deriveIssuerKey(v.master_seed_hex, "any-label");
    assert.equal(key.pub_p256_b64, v.expected_pub_p256_b64, `${v.name}: P-256`);
    assert.equal(key.pub_mldsa_b64, v.expected_pub_mldsa_b64, `${v.name}: ML-DSA-65`);
  }
});

test("the default key id is issuer: + the key-set root's first 32 hex", { skip }, () => {
  for (const v of doc().vectors) {
    const root = HolderKeySet.fromMasterSeed(v.master_seed_hex, v.tree_size).root;
    assert.equal(root, v.expected_holder_key_set_root, `${v.name}: root`);
    const key = issuerKeyOf({ seedHex: v.master_seed_hex, treeSize: v.tree_size });
    assert.equal(key.id, v.expected_default_key_id, `${v.name}: default key id`);
    assert.equal(key.pub_p256_b64, v.expected_pub_p256_b64, `${v.name}: P-256`);
    assert.equal(key.pub_mldsa_b64, v.expected_pub_mldsa_b64, `${v.name}: ML-DSA-65`);
  }
});

test("the key id is a label that never changes the key", { skip }, () => {
  for (const c of doc().key_id_cases) {
    const key = deriveIssuerKey(c.master_seed_hex, c.issuer_key_id);
    assert.equal(key.id, c.issuer_key_id, c.name);
    assert.equal(key.pub_p256_b64, c.expected_pub_p256_b64, `${c.name}: P-256`);
    assert.equal(key.pub_mldsa_b64, c.expected_pub_mldsa_b64, `${c.name}: ML-DSA-65`);

    // The same holds through the issuer's own configuration path.
    const configured = issuerKeyOf({ seedHex: c.master_seed_hex, issuerKeyId: c.issuer_key_id });
    assert.equal(configured.id, c.issuer_key_id, c.name);
    assert.equal(configured.pub_p256_b64, c.expected_pub_p256_b64, `${c.name}: P-256`);
    assert.equal(configured.pub_mldsa_b64, c.expected_pub_mldsa_b64, `${c.name}: ML-DSA-65`);
  }
});
