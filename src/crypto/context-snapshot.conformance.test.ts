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
 * The JSON-object subject profiles, against the contract.
 *
 * `subject.context-snapshot/1` canonical bytes, and for the three JSON-object
 * profiles the precondition's shared surface: every `negative_cases` entry is
 * refused and every `positive_cases` entry is accepted with its pinned canonical
 * bytes. A subject canonicalized differently produces a different subject digest,
 * which means a different commitment, which means a certificate that resolves to
 * nothing a verifier can reproduce.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { canonicalBytesForSubject, SUBJECT_CONTEXT_SNAPSHOT } from "./canonical-subject.js";
import { digestHexBytes } from "./digest.js";
import { jcsCanonicalizeBytes } from "./jcs.js";
import {
  SubjectPreconditionError,
  assertAiDecisionPrecondition,
  assertCollectionPrecondition,
  assertContextSnapshotPrecondition,
} from "./subject-json-preconditions.js";
import { siblingPath } from "../test-support/siblings.js";

function vectors(folder = "subject-context-snapshot"): any | null {
  const path = join(
    siblingPath(import.meta.url, "certcrypt-conformance", "fixtures", "primitives"),
    folder,
    "vectors.json"
  );
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

test("context-snapshot canonical bytes match the contract", () => {
  const v = vectors();
  if (v === null) return; // the sibling guard reports absence, loudly

  for (const vec of v.vectors) {
    const material = new TextEncoder().encode(JSON.stringify(vec.snapshot_object));
    const canonical = canonicalBytesForSubject(SUBJECT_CONTEXT_SNAPSHOT, material);
    assert.equal(
      new TextDecoder().decode(canonical),
      vec.expected_canonical_utf8,
      `context-snapshot '${vec.name}': canonical bytes diverged`
    );
    assert.equal(
      digestHexBytes(canonical),
      vec.subject_local_digest_hex,
      `context-snapshot '${vec.name}': subject digest diverged`
    );
  }
});

test("the profile id is the contract's", () => {
  const v = vectors();
  if (v === null) return;
  assert.equal(
    SUBJECT_CONTEXT_SNAPSHOT,
    v.profile,
    "the profile id is carried in the certificate, so a divergent one is not a mislabel"
  );
});

const JSON_PROFILES: [string, string, (v: unknown) => void][] = [
  ["subject-collection", "collection_subject", assertCollectionPrecondition],
  ["subject-ai-decision", "decision_record", assertAiDecisionPrecondition],
  ["subject-context-snapshot", "snapshot_object", assertContextSnapshotPrecondition],
];

for (const [folder, key, precondition] of JSON_PROFILES) {
  test(`${folder}: negative_cases are refused, positive_cases accepted as pinned`, () => {
    const v = vectors(folder);
    if (v === null) return;
    const negatives = v.negative_cases ?? [];
    assert.ok(negatives.length > 0, `${folder} carries no negative_cases`);
    for (const nc of negatives) {
      assert.throws(
        () => precondition(nc[key]),
        (e: unknown) => e instanceof SubjectPreconditionError,
        `${folder} negative case '${nc.name}' must be refused`
      );
    }
    for (const pc of v.positive_cases ?? []) {
      assert.doesNotThrow(() => precondition(pc[key]), `${folder} positive case '${pc.name}'`);
      const canonical = jcsCanonicalizeBytes(pc[key]);
      assert.equal(new TextDecoder().decode(canonical), pc.expected_canonical_bytes_utf8, pc.name);
      assert.equal(digestHexBytes(canonical), pc.expected_digest_hex, pc.name);
    }
  });
}
