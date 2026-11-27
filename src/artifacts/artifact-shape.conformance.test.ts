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
 * The field SET of the preimages this SDK signs, against the contract.
 *
 * Every other parity test here answers "are the bytes right?". This one answers
 * "are these the right fields at all?" — and it is the only check that fires at a
 * PRODUCER. An SDK that signs a preimage with one field too many computes a
 * perfectly correct digest over the wrong object: its own tests pass, the byte
 * vectors pass, and the divergence surfaces only when a verifier reconstructs the
 * full preimage and the signature fails.
 *
 * The check runs in both directions. Missing a field means signing fewer bytes
 * than the contract fixes; carrying an extra means signing more. Reading the
 * fields you know only proves you can find yours.
 */

import { existsSync, readFileSync } from "node:fs";
import assert from "node:assert/strict";
import test from "node:test";

import {
  projectedCommitmentSigningBytes,
  MAX_SUBMISSION_SET_MEMBERS,
} from "./capacity-evidence.js";
import { siblingPath } from "../test-support/siblings.js";

function vectors(family: string): any | null {
  const path = siblingPath(
    import.meta.url,
    "certcrypt-conformance",
    "fixtures",
    "primitives",
    family,
    "vectors.json"
  );
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

/** The field list the contract fixes for a named signed artifact. */
function declaredFields(shape: any, artifact: string): string[] {
  const entry = shape.artifacts.find((a: any) => a.artifact === artifact);
  assert.ok(entry, `the shape vector has no artifact named '${artifact}'`);
  return entry.fields;
}

test("the projected commitment this SDK signs has exactly the contract's fields", () => {
  const shape = vectors("artifact-shape");
  const evidence = vectors("capacity-evidence");
  if (shape === null || evidence === null) return;

  const declared = declaredFields(
    shape,
    "capacity.evidence/1 — projected commitment"
  );

  // Round-tripped through this SDK's own emitter, so what is compared is what it
  // would actually sign — not the fixture echoed back.
  const bytes = projectedCommitmentSigningBytes(evidence.projected_commitment);
  const emitted = Object.keys(JSON.parse(new TextDecoder().decode(bytes)));

  assert.deepEqual(
    emitted,
    declared,
    "the projected commitment this SDK signs differs from the contract's field set — " +
      "a field added or dropped here changes the signed bytes while every digest " +
      "stays internally correct"
  );
});

test("the emitted bytes are the ones the contract pins", () => {
  // The shape check above cannot see field ORDER, and this artifact is
  // insertion-ordered rather than JCS. Both checks are needed; neither replaces
  // the other.
  const evidence = vectors("capacity-evidence");
  if (evidence === null) return;

  const bytes = projectedCommitmentSigningBytes(evidence.projected_commitment);
  assert.equal(
    new TextDecoder().decode(bytes),
    evidence.expected_signing_bytes_utf8,
    "projected commitment signing bytes diverged — JCS vs insertion order, or field order"
  );
});

test("the member cap this SDK enforces is the contract's", () => {
  // Not a digest: a number that decides ADMISSION. An SDK capping at one value
  // and a service at another disagree about whether a set is well-formed, and the
  // disagreement surfaces as a rejection nobody can reproduce.
  const limits = vectors("submission-set-limits");
  if (limits === null) return;

  assert.equal(
    MAX_SUBMISSION_SET_MEMBERS,
    limits.member_cap.max_submission_set_members,
    "this SDK's member cap differs from the contract's"
  );
});

test("the system id this SDK signs into preimages is the contract's", () => {
  const limits = vectors("submission-set-limits");
  const evidence = vectors("capacity-evidence");
  if (limits === null || evidence === null) return;

  // It sits inside signed bytes, so a divergent value is not a mislabel — it is a
  // different digest.
  assert.equal(
    evidence.projected_commitment.system_id,
    limits.system_constants.system_id.value,
    "the contract's own vectors disagree about system_id"
  );
});
