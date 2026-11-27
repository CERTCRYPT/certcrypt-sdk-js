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
 * Preconditions for the three JSON-object subject profiles.
 *
 * These run at the canonicalization boundary — the last point where a
 * non-conformant subject can still be refused CHEAPLY. Past it the material is
 * committed to, signed, and eventually handed to a third party, so a precondition
 * that wrongly ACCEPTS produces a certificate that a conforming verifier rejects
 * later, in someone else's hands, for reasons the issuer can no longer fix.
 *
 * That asymmetry is why every rejection reason gets its own case and every case
 * asserts the SPECIFIC message: a check that fails for the wrong reason will pass
 * silently the day the reason it was meant to catch stops firing.
 *
 * The string-only discipline is the one to understand: every value at every depth
 * must be a JSON string, object or array. It is not fussiness — it is what keeps
 * RFC 8785 canonicalization free of number serialization, where implementations
 * disagree and cross-language byte parity dies.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertCollectionPrecondition,
  assertAiDecisionPrecondition,
  assertContextSnapshotPrecondition,
  SubjectPreconditionError,
} from "./subject-json-preconditions.js";

const HEX = "ab".repeat(32);
const NONCE_A = "1".repeat(64);
const NONCE_B = "2".repeat(64);

/** A minimal conforming collection: one leaf, cardinality "1". */
function collection(overrides: Record<string, unknown> = {}) {
  return {
    commitment_scheme: "collection.merkle-sha3-256/1",
    root: HEX,
    declared_cardinality: "1",
    leaves: [{ profile: "subject.text/1", commitment_digest_hex: HEX }],
    ...overrides,
  };
}

/** A minimal conforming ai-decision record. */
function aiDecision(overrides: Record<string, unknown> = {}) {
  return {
    profile: "subject.ai-decision/1",
    decision_id: "decision-1",
    decided_at: "2026-08-16T12:00:00.000Z",
    model: { id: "m-1", provider: "acme" },
    observation_scope: "client",
    input: [
      { id: "prompt", role: "user", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: NONCE_A, commitment_digest_hex: HEX },
    ],
    output: [
      { id: "answer", role: "assistant", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: NONCE_B, commitment_digest_hex: HEX },
    ],
    decision: "approved",
    ...overrides,
  };
}

/** Assert the call throws a SubjectPreconditionError whose message matches. */
function refuses(fn: () => void, pattern: RegExp) {
  assert.throws(fn, (e: Error) => {
    assert.ok(
      e instanceof SubjectPreconditionError,
      `expected SubjectPreconditionError, got ${e.name}: ${e.message}`
    );
    assert.match(e.message, pattern);
    return true;
  });
}

// --- subject.collection/1 --------------------------------------------------

test("a conforming collection passes", () => {
  assert.doesNotThrow(() => assertCollectionPrecondition(collection()));
});

test("collection: a non-object subject is refused", () => {
  for (const v of ["a string", 42, null, [], true]) {
    refuses(() => assertCollectionPrecondition(v), /not a JSON object/);
  }
});

test("collection: each of the four members is required", () => {
  for (const missing of ["commitment_scheme", "root", "declared_cardinality", "leaves"]) {
    const subject = collection();
    delete (subject as Record<string, unknown>)[missing];
    refuses(() => assertCollectionPrecondition(subject), new RegExp(`missing member "${missing}"`));
  }
});

test("collection: an extra member is refused (exactly four allowed)", () => {
  refuses(
    () => assertCollectionPrecondition(collection({ extra: "nope" })),
    /unexpected member "extra"/
  );
});

test("collection: the three string members must be strings", () => {
  for (const k of ["commitment_scheme", "root", "declared_cardinality"]) {
    refuses(
      () => assertCollectionPrecondition(collection({ [k]: { not: "a string" } })),
      new RegExp(`member "${k}" must be a string`)
    );
  }
});

test("collection: leaves must be a non-empty array", () => {
  refuses(() => assertCollectionPrecondition(collection({ leaves: [] })), /non-empty array/);
  refuses(() => assertCollectionPrecondition(collection({ leaves: "x" })), /non-empty array/);
});

test("collection: each leaf must be an object with exactly its two members", () => {
  refuses(() => assertCollectionPrecondition(collection({ leaves: ["x"], declared_cardinality: "1" })), /must be an object/);
  refuses(
    () =>
      assertCollectionPrecondition(
        collection({ leaves: [{ profile: "subject.text/1" }] })
      ),
    /exactly "profile" and "commitment_digest_hex"/
  );
  refuses(
    () =>
      assertCollectionPrecondition(
        collection({
          leaves: [{ profile: "subject.text/1", commitment_digest_hex: HEX, extra: "x" }],
        })
      ),
    /exactly "profile" and "commitment_digest_hex"/
  );
});

test("collection: a leaf digest must be 64 LOWERCASE hex characters", () => {
  // Uppercase is the trap: it looks right and hashes to something else, so a
  // verifier recomputing the root would disagree byte-for-byte.
  for (const bad of [HEX.toUpperCase(), "ab", `${HEX}ff`, "z".repeat(64)]) {
    refuses(
      () =>
        assertCollectionPrecondition(
          collection({ leaves: [{ profile: "subject.text/1", commitment_digest_hex: bad }] })
        ),
      /64 lowercase hex/
    );
  }
});

test("collection: declared_cardinality must be canonical base-10", () => {
  // No sign, no leading zeros, not zero. A non-canonical spelling would still
  // parse as a number but is a different STRING, and the string is what is signed.
  for (const bad of ["0", "01", "+1", "-1", "1.0", "1e3", " 1", "1 ", ""]) {
    refuses(
      () => assertCollectionPrecondition(collection({ declared_cardinality: bad })),
      /canonical unsigned base-10/
    );
  }
});

test("collection: declared_cardinality may not exceed 2^64 − 1", () => {
  refuses(
    () => assertCollectionPrecondition(collection({ declared_cardinality: "18446744073709551616" })),
    /exceeds 2\^64/
  );
});

test("collection: declared_cardinality must AGREE with the leaf count", () => {
  // The economic layer bills on the declaration, so it must match rather than be
  // derived — a mismatch is how an issuer would under-declare what it certified.
  refuses(
    () => assertCollectionPrecondition(collection({ declared_cardinality: "2" })),
    /does not equal the number of leaves/
  );
});

test("collection: under the sha3-256 scheme the root must be 64 lowercase hex", () => {
  refuses(() => assertCollectionPrecondition(collection({ root: "short" })), /"root" must be a 64-character/);
  refuses(
    () => assertCollectionPrecondition(collection({ root: HEX.toUpperCase() })),
    /"root" must be a 64-character/
  );
});

test("collection: an unknown commitment_scheme does not trigger the sha3 root check", () => {
  // The root shape is scheme-specific: a future scheme must not be rejected by a
  // rule that only applies to this one.
  assert.doesNotThrow(() =>
    assertCollectionPrecondition(
      collection({ commitment_scheme: "some.future.scheme/1", root: "not-hex-at-all" })
    )
  );
});

// --- the string-only discipline (shared by all three profiles) -------------

test("context-snapshot: numbers are refused at any depth; booleans and nulls are not", () => {
  // The rule exists for one reason, stated in subject.context-snapshot/1 §7.1:
  // JSON NUMBER serialization is the hardest part of RFC 8785 to reproduce
  // byte-identically across languages. Booleans and nulls carry no such hazard —
  // they canonicalize identically everywhere — and §7 positively requires
  // preserving "the exact string, boolean, array, object, and null semantics of
  // the input", while §8 forbids coercing "booleans or nulls into strings".
  //
  // CCVP/1 §7.1 depends on that: its normative entry example carries
  // `valid_to: null` for an open-ended eligibility window, and §8 reads
  // `entry.valid_to is not null`. Refusing nulls would make the governing
  // protocol's own example unrepresentable.
  for (const shape of [
    { a: 1 },
    { a: { b: 1 } },
    { a: [1] },
  ]) {
    refuses(() => assertContextSnapshotPrecondition(shape), /JSON number/);
  }
  for (const ok of [
    { a: true },
    { a: false },
    { a: null },
    { a: { b: null } },
    { a: [true, null] },
  ]) {
    assert.doesNotThrow(() => assertContextSnapshotPrecondition(ok));
  }
});

test("context-snapshot: the error names the PATH, so a deep offender is findable", () => {
  // A snapshot can be large; "somewhere there is a number" would not be actionable.
  refuses(() => assertContextSnapshotPrecondition({ a: { b: [{ c: 7 }] } }), /a\.b\[0\]\.c/);
});

test("string-only: strings, nested objects and arrays are all accepted", () => {
  assert.doesNotThrow(() =>
    assertContextSnapshotPrecondition({
      a: "x",
      b: { c: "y", d: ["e", { f: "g" }] },
      e: [],
      f: {},
    })
  );
});

test("context-snapshot: a non-object is refused, but the member set is NOT fixed", () => {
  // This profile deliberately fixes only the value discipline: its shape is
  // governed by the higher-layer protocol, so arbitrary members must pass.
  refuses(() => assertContextSnapshotPrecondition("nope"), /not a JSON object/);
  assert.doesNotThrow(() => assertContextSnapshotPrecondition({ anything: "goes" }));
});

// --- subject.ai-decision/1 -------------------------------------------------

test("a conforming ai-decision record passes, with and without optionals", () => {
  assert.doesNotThrow(() => assertAiDecisionPrecondition(aiDecision()));
  assert.doesNotThrow(() =>
    assertAiDecisionPrecondition(
      aiDecision({
        parameters: { temperature: "0.2" },
        context: { purpose_ref: "purpose-7", oversight_ref: "review-2" },
        started_at: "2026-08-16T11:59:58.000Z",
        actor_id: "user-1",
        policy_ref: "policy-7",
        model: { id: "m-1", provider: "acme", version: "2026-01" },
      })
    )
  );
});

test("ai-decision: every required member is required", () => {
  for (const missing of [
    "profile",
    "decision_id",
    "decided_at",
    "model",
    "observation_scope",
    "input",
    "output",
    "decision",
  ]) {
    const record = aiDecision();
    delete (record as Record<string, unknown>)[missing];
    refuses(
      () => assertAiDecisionPrecondition(record),
      new RegExp(`missing required member "${missing}"`)
    );
  }
});

test("ai-decision: an unexpected member is refused", () => {
  refuses(() => assertAiDecisionPrecondition(aiDecision({ extra: "x" })), /unexpected member "extra"/);
});

test("ai-decision: profile must name this exact profile", () => {
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ profile: "subject.text/1" })),
    /"profile" must equal/
  );
});

test("ai-decision: model and material parts have closed shapes", () => {
  refuses(() => assertAiDecisionPrecondition(aiDecision({ model: "m" })), /"model" must be an object/);
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ model: { id: "m" } })),
    /"model" missing member "provider"/
  );
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ model: { id: "m", provider: "p", nope: "x" } })),
    /"model" has unexpected member "nope"/
  );
  for (const model of [
    { id: "", provider: "p" },
    { id: "m", provider: "" },
    { id: "m", provider: "p", version: "" },
  ]) {
    refuses(() => assertAiDecisionPrecondition(aiDecision({ model })), /model\..*must not be empty/);
  }
  refuses(() => assertAiDecisionPrecondition(aiDecision({ decision: "" })), /decision.*must not be empty/);
  refuses(() => assertAiDecisionPrecondition(aiDecision({ input: [] })), /non-empty array/);
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ input: [{ id: "prompt", role: "user", media_type: "text/plain", profile: "subject.text\/1", material_nonce_hex: NONCE_A }] })),
    /missing member "commitment_digest_hex"/,
  );
});

test("ai-decision: parameters must be an object when present", () => {
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ parameters: "not-an-object" })),
    /"parameters" must be an object/
  );
});

test("ai-decision: parameters members must be flat strings", () => {
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ parameters: { stop: ["a"] } })),
    /"parameters\.stop" must be a string/
  );
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ parameters: { nested: { x: "1" } } })),
    /"parameters\.nested" must be a string/
  );
});

test("ai-decision: context is a bounded flat string map", () => {
  refuses(() => assertAiDecisionPrecondition(aiDecision({ context: { nested: { x: "1" } } })), /"context\.nested" must be a string/);
  const tooMany = Object.fromEntries(Array.from({ length: 129 }, (_, i) => [`k${i}`, "v"]));
  refuses(() => assertAiDecisionPrecondition(aiDecision({ context: tooMany })), /at most 128/);
});

test("ai-decision: nonce and commitment must be 64 lowercase hex characters", () => {
  for (const bad of ["aa", "A".repeat(64), "g".repeat(64)]) {
    refuses(
      () => assertAiDecisionPrecondition(aiDecision({ input: [{ id: "prompt", role: "user", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: bad, commitment_digest_hex: HEX }] })),
      /"input\[0\]\.material_nonce_hex" must be 64 lowercase hex/
    );
    refuses(
      () => assertAiDecisionPrecondition(aiDecision({ input: [{ id: "prompt", role: "user", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: NONCE_A, commitment_digest_hex: bad }] })),
      /"input\[0\]\.commitment_digest_hex" must be 64 lowercase hex/
    );
  }
});

test("ai-decision: legacy digest_hex is refused by the closed part shape", () => {
  refuses(
    () => assertAiDecisionPrecondition(aiDecision({ input: [{
      id: "prompt",
      role: "user",
      media_type: "text/plain",
      profile: "subject.text/1",
      material_nonce_hex: NONCE_A,
      digest_hex: HEX,
    }] })),
    /missing member "commitment_digest_hex"/,
  );
});

test("ai-decision: material profiles are closed and binary media is allowed", () => {
  for (const profile of ["subject.collection/1", "subject.context-snapshot/1", "subject.unknown/1"]) {
    refuses(
      () => assertAiDecisionPrecondition(aiDecision({ output: [{ id: "answer", role: "assistant", media_type: "text/plain", profile, material_nonce_hex: NONCE_B, commitment_digest_hex: HEX }] })),
      /not an admitted material profile/
    );
  }
  for (const profile of ["subject.binary/1", "subject.email/1", "subject.ai-decision/1"]) {
    assert.doesNotThrow(() => assertAiDecisionPrecondition(aiDecision({ input: [{ id: "payload", role: "user", media_type: "application/octet-stream", profile, material_nonce_hex: NONCE_A, commitment_digest_hex: HEX }] })));
  }
});

test("ai-decision: times are real UTC milliseconds and ordered", () => {
  for (const bad of ["2026-02-30T12:00:00.000Z", "2026-08-16T12:00:00Z", "2026-08-16T12:00:00.5Z", "2026-08-16T12:00:00.0000Z", "2026-08-16T12:00:00.000+02:00"]) {
    refuses(() => assertAiDecisionPrecondition(aiDecision({ decided_at: bad })), /"decided_at"/);
  }
  refuses(() => assertAiDecisionPrecondition(aiDecision({ started_at: "2026-08-16T12:00:00.001Z" })), /must not be after/);
});

test("ai-decision: part ids are globally unique and MIME essences are canonical", () => {
  refuses(() => assertAiDecisionPrecondition(aiDecision({ decision_id: "Bad ID" })), /decision_id/);
  refuses(() => assertAiDecisionPrecondition(aiDecision({ output: [{ id: "prompt", role: "assistant", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: NONCE_B, commitment_digest_hex: HEX }] })), /duplicated/);
  refuses(() => assertAiDecisionPrecondition(aiDecision({ input: [{ id: "prompt", role: "user", media_type: "Text/Plain; charset=utf-8", profile: "subject.text/1", material_nonce_hex: NONCE_A, commitment_digest_hex: HEX }] })), /lowercase MIME essence/);
  assert.doesNotThrow(() => assertAiDecisionPrecondition(aiDecision({ input: [{ id: "image", role: "user", media_type: "image/png", profile: "subject.binary/1", material_nonce_hex: NONCE_A, commitment_digest_hex: HEX }] })));
  refuses(() => assertAiDecisionPrecondition(aiDecision({ output: [{ id: "answer", role: "assistant", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: NONCE_A, commitment_digest_hex: HEX }] })), /material nonce.*duplicated/);
});

test("ai-decision: observation scope is explicit", () => {
  assert.doesNotThrow(() => assertAiDecisionPrecondition(aiDecision({ observation_scope: "runtime" })));
  refuses(() => assertAiDecisionPrecondition(aiDecision({ observation_scope: "provider" })), /client.*runtime/);
});

test("ai-decision: a non-object record is refused", () => {
  refuses(() => assertAiDecisionPrecondition([]), /not a JSON object/);
  refuses(() => assertAiDecisionPrecondition(null), /not a JSON object/);
});

test("ai-decision: the string-only rule applies to it too", () => {
  refuses(() => assertAiDecisionPrecondition(aiDecision({ decision: 1 })), /JSON number/);
});
