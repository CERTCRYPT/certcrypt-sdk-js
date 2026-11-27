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
 * Context snapshot certificates and the CCVP/1 declared context, checked
 * against the conformance vectors where they pin bytes and by construction
 * where they pin shape.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { siblingPath } from "../test-support/siblings.js";
import { digestHexBytes, digestHexText } from "../crypto/digest.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import {
  assembleBaseCertificate,
  assembleContextSnapshotCertificate,
  generateIssuerKey,
  issuerKeyFingerprintHex,
} from "./base-certificate.js";

const VECTORS = siblingPath(
  import.meta.url, "certcrypt-conformance", "fixtures", "primitives", "ccvp-consistency", "vectors.json"
);
const NONCE = "ab".repeat(32);
const DOMAIN = { system_id: "certcrypt", rules_version: "rules/conformance" };
const SNAPSHOT = {
  context_set_id: "invoices",
  snapshot_id: "01JAN0000000000000000000AA",
  issued_at: "2026-01-01T00:00:00Z",
  entries: [],
};

test("issuerKeyFingerprintHex reproduces the composite key fingerprints of the vectors", () => {
  if (!existsSync(VECTORS)) return;
  const v = JSON.parse(readFileSync(VECTORS, "utf-8"));
  for (const k of Object.values<any>(v.keys)) {
    assert.equal(issuerKeyFingerprintHex(k), k.composite_key_fingerprint_digest_hex);
  }
});

test("a context snapshot certificate carries the snapshot and one subject committing to it", () => {
  const key = generateIssuerKey("context:test");
  const cert = assembleContextSnapshotCertificate({
    snapshot: SNAPSHOT, issuerKey: key, nonce_hex: NONCE, issued_at: "2026-01-01T00:00:00Z", ...DOMAIN,
  }).base_certificate;
  assert.deepEqual(cert.payload.snapshot, SNAPSHOT);
  assert.equal(cert.payload.anchor.subjects.length, 1);
  assert.equal(cert.payload.anchor.subjects[0].profile, "subject.context-snapshot/1");
  const local = digestHexBytes(jcsCanonicalizeBytes(SNAPSHOT));
  assert.equal(cert.payload.anchor.subjects[0].commitment_digest_hex, digestHexText(NONCE + local));
  assert.equal(cert.signatures[0].signer.id, "context:test");
});

test("a snapshot outside the CCVP/1 shape is refused before signing", () => {
  const key = generateIssuerKey("context:test");
  const mint = (snapshot: Record<string, unknown>) =>
    assembleContextSnapshotCertificate({
      snapshot, issuerKey: key, nonce_hex: NONCE, issued_at: "2026-01-01T00:00:00Z", ...DOMAIN,
    });
  assert.throws(() => mint({ ...SNAPSHOT, snapshot_id: "" }), /snapshot_id/);
  assert.throws(() => mint({ ...SNAPSHOT, issued_at: "2026-01-01T00:00:00+00:00" }), /issued_at/);
  assert.throws(() => mint({ ...SNAPSHOT, entries: [{ issuer_id: "a" }] }), /pub_fingerprint_digest_hex/);
  // subject.context-snapshot/1 §7.1: no JSON number anywhere.
  assert.throws(() => mint({ ...SNAPSHOT, revision: 2 }));
});

test("a declared context is signed into the payload, and a malformed one is refused", () => {
  const key = generateIssuerKey("issuer:test");
  const context = {
    snapshot_issuer_id: "context:test",
    snapshot_issuer_fingerprint_digest_hex: "cd".repeat(32),
    context_set_id: "invoices",
  };
  const base = {
    subjects: [{ profile: "subject.binary/1", material: new Uint8Array([1]) }],
    nonce_hex: NONCE, issued_at: "2026-04-12T10:00:00Z", ...DOMAIN, issuerKey: key,
  };
  assert.deepEqual(assembleBaseCertificate({ ...base, context }).base_certificate.payload.context, context);
  assert.equal("context" in assembleBaseCertificate(base).base_certificate.payload, false);
  assert.throws(
    () => assembleBaseCertificate({ ...base, context: { ...context, snapshot_issuer_fingerprint_digest_hex: "x" } }),
    /fingerprint/,
  );
});
