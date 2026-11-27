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
 * CCVP/1 end to end: the SDK mints a context snapshot certificate and a target
 * certificate that names it, and the verifier toolkit's `verifyConsistency`
 * resolves them. Expects the toolkit as a sibling checkout, built.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { siblingPath, missingSibling } from "../test-support/siblings.js";
import {
  assembleBaseCertificate,
  assembleContextSnapshotCertificate,
  generateIssuerKey,
  generateNonceHex,
  issuerKeyFingerprintHex,
  type IssuerKey,
} from "./base-certificate.js";

const TOOLKIT_DIST = siblingPath(import.meta.url, "certcrypt-verifier-toolkit-js", "dist", "core");
const skip = missingSibling(import.meta.url, "certcrypt-verifier-toolkit-js", "dist", "core");

async function loadToolkit(): Promise<{ verifyConsistency: any; config: any }> {
  const mldsa = await import(pathToFileURL(resolve(TOOLKIT_DIST, "crypto/ml-dsa.js")).href);
  if (!(await mldsa.initMlDsa65())) throw new Error("toolkit ML-DSA-65 backend unavailable");
  const mod = await import(pathToFileURL(resolve(TOOLKIT_DIST, "consistency/verify-consistency.js")).href);
  const cfg = await import(pathToFileURL(resolve(TOOLKIT_DIST, "..", "harness", "profiles.js")).href);
  return { verifyConsistency: mod.verifyConsistency, config: cfg.getConformanceConfig() };
}

const DOMAIN = { system_id: "certcrypt", rules_version: "rules/conformance" };

function snapshotFor(issuer: IssuerKey, contextKey: IssuerKey) {
  return assembleContextSnapshotCertificate({
    snapshot: {
      context_set_id: "invoices",
      snapshot_id: "01JAN0000000000000000000AA",
      issued_at: "2026-01-01T00:00:00Z",
      entries: [{
        issuer_id: issuer.id,
        pub_fingerprint_digest_hex: issuerKeyFingerprintHex(issuer),
        status: "active",
        valid_from: "2026-01-01T00:00:00Z",
        valid_to: null,
      }],
    },
    issuerKey: contextKey,
    nonce_hex: generateNonceHex(),
    issued_at: "2026-01-01T00:00:00Z",
    ...DOMAIN,
  }).base_certificate;
}

function targetFor(issuer: IssuerKey, contextKey: IssuerKey) {
  return assembleBaseCertificate({
    subjects: [{ profile: "subject.binary/1", material: new Uint8Array([1, 2, 3]) }],
    nonce_hex: generateNonceHex(),
    issued_at: "2026-04-12T10:00:00Z",
    context: {
      snapshot_issuer_id: contextKey.id,
      snapshot_issuer_fingerprint_digest_hex: issuerKeyFingerprintHex(contextKey),
      context_set_id: "invoices",
    },
    ...DOMAIN,
    issuerKey: issuer,
  }).base_certificate;
}

test("an SDK-minted snapshot covers an SDK-minted certificate that names it", { skip }, async () => {
  const { verifyConsistency, config } = await loadToolkit();
  const issuer = generateIssuerKey("issuer:acme");
  const contextKey = generateIssuerKey("context:acme-programme");
  const r = verifyConsistency(targetFor(issuer, contextKey), [snapshotFor(issuer, contextKey)], config);
  assert.equal(r.outcome, "consistency-match", r.reason);
});

test("a snapshot signed by another key under the same label does not govern", { skip }, async () => {
  const { verifyConsistency, config } = await loadToolkit();
  const issuer = generateIssuerKey("issuer:acme");
  const contextKey = generateIssuerKey("context:acme-programme");
  const impostor = generateIssuerKey("context:acme-programme");
  const r = verifyConsistency(targetFor(issuer, contextKey), [snapshotFor(issuer, impostor)], config);
  assert.equal(r.outcome, "consistency-unknown", r.reason);
});
