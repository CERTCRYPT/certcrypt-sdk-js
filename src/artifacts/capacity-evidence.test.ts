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
  assembleEvidence,
  assembleZeroDataSubmissionSet,
  assertSubmissionSetWithinBound,
  evidenceDigestHex,
  projectedCommitmentSigningBytes,
  MAX_SUBMISSION_SET_MEMBERS,
  SubmissionSetTooLargeError,
  type SignedLevel1Binding,
} from "./capacity-evidence.js";
import { HolderKeySet } from "./holder-keyset.js";
import { derivePseudonym } from "../crypto/pseudonym.js";
import { computeLeafHash, verifyInclusionProof } from "../crypto/merkle.js";
import { verifyMlDsa65 } from "../crypto/ml-dsa.js";

const FIXTURE = ["fixtures", "primitives", "capacity-evidence", "golden-e2e.json"];
const GOLDEN_PATH = siblingPath(import.meta.url, "certcrypt-conformance", ...FIXTURE);
const skip = missingSibling(import.meta.url, "certcrypt-conformance", ...FIXTURE);

// The stable identifiers the published conformance vector projects. These are the
// PREIMAGES of the pseudonyms pinned in the golden fixture, so they are fixed by
// that vector and cannot be renamed here: change one and the pseudonym it derives
// no longer matches. Synthetic values from the conformance suite — not identifiers
// of any real issuer.
const GOLDEN_HOLDER_ID = "holder:example";
const GOLDEN_POOL_ID = "pool:example-default";
const GOLDEN_AUTH_ID = "auth:example-2026";

interface Golden {
  evidence: {
    operation_salt_hex: string;
    projected_commitment: {
      holder_pseudonym: string;
      pool_pseudonym: string;
      authorization_pseudonym: string;
    };
  };
}

function loadGolden(): Golden {
  return JSON.parse(readFileSync(GOLDEN_PATH, "utf-8")) as Golden;
}

test("CONFORMANCE: pseudonyms reproduce the capacity-evidence golden byte-for-byte", {skip}, () => {
  const g = loadGolden();
  const salt = Buffer.from(g.evidence.operation_salt_hex, "hex");
  const pc = g.evidence.projected_commitment;

  assert.equal(
    derivePseudonym(salt, "holder", GOLDEN_HOLDER_ID),
    pc.holder_pseudonym,
    "holder pseudonym diverged from the golden"
  );
  assert.equal(
    derivePseudonym(salt, "pool", GOLDEN_POOL_ID),
    pc.pool_pseudonym,
    "pool pseudonym diverged from the golden"
  );
  assert.equal(
    derivePseudonym(salt, "authorization", GOLDEN_AUTH_ID),
    pc.authorization_pseudonym,
    "authorization pseudonym diverged from the golden"
  );
});

// A toy pre-signed Level-1 anchor: in production this comes from the holder-auth
// endpoint. For these tests the signature value is opaque (the SDK never
// verifies Level-1; it carries it verbatim), so we use a fixed root-bound stub.
function toySignedLevel1(root: string): SignedLevel1Binding {
  return {
    level1_binding: {
      system_id: "certcrypt",
      rules_version: "rules/2026-01",
      system_root_fingerprint: "ab".repeat(32),
      authorized_role: "capacity_commitment_holder",
      authorization_issuer_kid: "system-domain-kid-1",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2027-01-01T00:00:00Z",
      holder_key_set_root: root,
    },
    level1_signature: {
      alg: "certcrypt-composite-p256-mldsa65-v1",
      mode: "AND",
      signatures: [
        { alg: "ECDSA-P256-SHA3-256", encoding: "raw-rs-64", low_s: true, sig_b64: "AAAA" },
        { alg: "ML-DSA-65", sig_b64: "AAAA" },
      ],
    },
  };
}

function sampleEvidence(keySet: HolderKeySet, leafIndex: number) {
  return assembleEvidence({
    signedLevel1: toySignedLevel1(keySet.root),
    certificate_commitment_digest: "ef".repeat(32),
    consumed_quantity: "5.00",
    declared_effective_units: "1",
    issued_at: "2026-06-15T12:00:00Z",
    expires_at: "2026-07-15T12:00:00Z",
    stable: {
      holder_id: GOLDEN_HOLDER_ID,
      pool_id: GOLDEN_POOL_ID,
      authorization_id: GOLDEN_AUTH_ID,
    },
    keySet,
    leafIndex,
    operationSalt: new TextEncoder().encode("op-salt-1"),
  });
}

test("assembled evidence is internally consistent (membership + L3 signature + pseudonym bindings)", () => {
  const keySet = HolderKeySet.generate(4);
  const ev = sampleEvidence(keySet, 0);

  assert.equal(ev.profile, "zero-data.unlinkable");

  // The disclosed leaf is a member of the authorized root.
  const leafHash = computeLeafHash(
    Buffer.from(ev.operation_key.public_key_b64, "base64")
  );
  assert.ok(
    verifyInclusionProof(
      leafHash,
      ev.operation_key.leaf_index,
      ev.operation_key.inclusion_proof,
      keySet.root,
      ev.operation_key.tree_size
    ),
    "operation key must be a member of the authorized root"
  );

  // The Level-3 signature verifies against the disclosed leaf key over the
  // projected commitment's signing bytes.
  const leafPk = Buffer.from(ev.operation_key.public_key_b64, "base64");
  const sig = Buffer.from(ev.commitment_signature_b64, "base64");
  assert.ok(
    verifyMlDsa65(leafPk, projectedCommitmentSigningBytes(ev.projected_commitment), sig),
    "commitment signature must verify against the disclosed leaf key"
  );

  // Pseudonym bindings agree between commitment and authorization.
  assert.equal(
    ev.projected_commitment.holder_pseudonym,
    ev.projected_authorization.holder_pseudonym
  );
  assert.equal(
    ev.projected_commitment.authorization_pseudonym,
    ev.projected_authorization.authorization_pseudonym
  );

  // The carried Level-1 anchor is the one we passed in, verbatim.
  assert.equal(
    ev.projected_authorization.holder_key_set_root,
    keySet.root
  );
});

test("no stable identifier appears in the serialized evidence", () => {
  const keySet = HolderKeySet.generate(4);
  const ev = sampleEvidence(keySet, 1);
  const json = JSON.stringify(ev);
  assert.ok(!json.includes(GOLDEN_HOLDER_ID), "holder_id must not leak");
  assert.ok(!json.includes(GOLDEN_POOL_ID), "pool_id must not leak");
  assert.ok(!json.includes(GOLDEN_AUTH_ID), "authorization_id must not leak");
});

test("two operations under different salts/leaves are unlinkable by key and pseudonym", () => {
  const keySet = HolderKeySet.generate(4);
  const e1 = assembleEvidence({
    signedLevel1: toySignedLevel1(keySet.root),
    certificate_commitment_digest: "ef".repeat(32),
    consumed_quantity: "5.00",
    declared_effective_units: "1",
    issued_at: "2026-06-15T12:00:00Z",
    expires_at: "2026-07-15T12:00:00Z",
    stable: { holder_id: "h", pool_id: "p", authorization_id: "a" },
    keySet,
    leafIndex: 0,
    operationSalt: new TextEncoder().encode("salt-A"),
  });
  const e2 = assembleEvidence({
    signedLevel1: toySignedLevel1(keySet.root),
    certificate_commitment_digest: "ef".repeat(32),
    consumed_quantity: "5.00",
    declared_effective_units: "1",
    issued_at: "2026-06-15T12:00:00Z",
    expires_at: "2026-07-15T12:00:00Z",
    stable: { holder_id: "h", pool_id: "p", authorization_id: "a" },
    keySet,
    leafIndex: 1,
    operationSalt: new TextEncoder().encode("salt-B"),
  });
  assert.notEqual(
    e1.projected_commitment.holder_pseudonym,
    e2.projected_commitment.holder_pseudonym
  );
  assert.notEqual(
    e1.operation_key.public_key_b64,
    e2.operation_key.public_key_b64
  );
});

test("evidence digest is deterministic and stable across re-serialization", () => {
  const keySet = HolderKeySet.generate(2);
  const ev = sampleEvidence(keySet, 0);
  assert.equal(evidenceDigestHex(ev), evidenceDigestHex(ev));
  assert.match(evidenceDigestHex(ev), /^[0-9a-f]{64}$/);
});

test("zero-data submission set wraps the evidence + operative context, stable id", () => {
  const keySet = HolderKeySet.generate(4);
  const ev = sampleEvidence(keySet, 0);
  const set = assembleZeroDataSubmissionSet(
    ev,
    { holder_id: GOLDEN_HOLDER_ID, pool_id: GOLDEN_POOL_ID },
    {
      rules_version: "rules/2026-01",
      system_root_fingerprint: "ab".repeat(32),
      closure_time: new Date("2026-06-15T12:30:00Z"),
    }
  );

  assert.equal(set.schema, "submission-set/1");
  assert.equal(set.closure_time, "2026-06-15T12:30:00Z");
  assert.match(set.submission_set_id, /^[0-9a-f]{64}$/);
  assert.equal(set.certificates.length, 1);
  // The canonical member is exactly capacity_evidence + operative
  // (submission-set/1 §7.1): the shape and the submission_set_id are fixed together.
  assert.deepEqual(Object.keys(set.certificates[0]).sort(), [
    "capacity_evidence",
    "operative",
  ]);
  // The evidence travels inside the certificate; there is no top-level
  // holder_authorizations slice (the projected authorization is in the evidence).
  assert.equal(set.certificates[0].capacity_evidence.profile, "zero-data.unlinkable");

  // SYSTEM-DOMAIN AGNOSTICISM: the set's system_id comes from the SIGNED evidence,
  // not from a constant in this SDK.
  assert.equal(set.system_id, ev.projected_commitment.system_id);
  assert.ok(!("holder_authorizations" in set));
  // Operative context travels alongside, NOT inside the evidence — that is what
  // keeps the evidence zero-data.
  assert.equal(set.certificates[0].operative.pool_id, GOLDEN_POOL_ID);
  const evidenceJson = JSON.stringify(set.certificates[0].capacity_evidence);
  assert.ok(!evidenceJson.includes(GOLDEN_HOLDER_ID), "operative ids must not be in the evidence");

  // submission_set_id is deterministic.
  const set2 = assembleZeroDataSubmissionSet(
    ev,
    { holder_id: GOLDEN_HOLDER_ID, pool_id: GOLDEN_POOL_ID },
    {
      rules_version: "rules/2026-01",
      system_root_fingerprint: "ab".repeat(32),
      closure_time: new Date("2026-06-15T12:30:00Z"),
    }
  );
  assert.equal(set.submission_set_id, set2.submission_set_id);
});

test("submission set takes its system_id from the evidence, not from a hardcoded domain", () => {
  // A conforming operator on ANOTHER system domain. A fixed "certcrypt" here,
  // whoever authorized the holder, would make the set misreport its domain AND,
  // since system_id is covered by the submission_set_id digest, compute the
  // wrong id.
  const keySet = HolderKeySet.generate(4);
  const ev = sampleEvidence(keySet, 0);
  const foreign = "acme-notary";
  ev.projected_commitment.system_id = foreign;
  ev.projected_authorization.system_id = foreign;

  const set = assembleZeroDataSubmissionSet(
    ev,
    { holder_id: GOLDEN_HOLDER_ID, pool_id: GOLDEN_POOL_ID },
    {
      rules_version: "rules/2026-01",
      system_root_fingerprint: "cd".repeat(32),
      closure_time: new Date("2026-06-15T12:30:00Z"),
    }
  );

  assert.equal(set.system_id, foreign, "the set must carry the issuer's own domain");
  assert.notEqual(set.system_id, "certcrypt");
});

test("submission set refuses evidence whose two projections disagree on the domain", () => {
  // The spec requires (system_id, rules_version, system_root_fingerprint) to agree
  // between the projections — anti-splicing. A mismatch means the halves came from
  // different authorizations and must fail BEFORE anything is signed or sent.
  const keySet = HolderKeySet.generate(4);
  const ev = sampleEvidence(keySet, 0);
  ev.projected_commitment.system_id = "domain-a";
  ev.projected_authorization.system_id = "domain-b";

  assert.throws(
    () =>
      assembleZeroDataSubmissionSet(
        ev,
        { holder_id: GOLDEN_HOLDER_ID, pool_id: GOLDEN_POOL_ID },
        {
          rules_version: "rules/2026-01",
          system_root_fingerprint: "cd".repeat(32),
          closure_time: new Date("2026-06-15T12:30:00Z"),
        }
      ),
    /system_id mismatch/
  );
});

test("key set root mismatch with the Level-1 binding fails early", () => {
  const keySet = HolderKeySet.generate(2);
  const other = HolderKeySet.generate(2);
  assert.throws(() =>
    assembleEvidence({
      signedLevel1: toySignedLevel1(other.root), // wrong root
      certificate_commitment_digest: "ef".repeat(32),
      consumed_quantity: "5.00",
      declared_effective_units: "1",
      issued_at: "2026-06-15T12:00:00Z",
      expires_at: "2026-07-15T12:00:00Z",
      stable: { holder_id: "h", pool_id: "p", authorization_id: "a" },
      keySet,
      leafIndex: 0,
      operationSalt: new TextEncoder().encode("op-salt-1"),
    })
  );
});

test("submission-set bound: MAX is 64 and the guard fails fast over it", () => {
  assert.equal(MAX_SUBMISSION_SET_MEMBERS, 64);
  // within bound: no throw
  assertSubmissionSetWithinBound(1);
  assertSubmissionSetWithinBound(MAX_SUBMISSION_SET_MEMBERS);
  // over bound: typed throw
  assert.throws(
    () => assertSubmissionSetWithinBound(MAX_SUBMISSION_SET_MEMBERS + 1),
    (e: unknown) =>
      e instanceof SubmissionSetTooLargeError &&
      e.count === MAX_SUBMISSION_SET_MEMBERS + 1 &&
      e.max === MAX_SUBMISSION_SET_MEMBERS
  );
});
