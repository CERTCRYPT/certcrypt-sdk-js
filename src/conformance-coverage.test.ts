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
 * Which primitive families this SDK accounts for, and why.
 *
 * The parity tests answer "do the bytes match?". This file answers the question
 * that comes before it: "is anyone checking this family at all?". A family can
 * be added to the contract without any implementation reading it, and nothing
 * fails, because nothing requires anyone to. A contract can outgrow its
 * consumers in silence, and only a check like this one makes that loud.
 *
 * This SDK is on the ISSUER side of the role table in the conformance README: it
 * mints certificates and capacity evidence. Verifier-only families do not apply,
 * and holding it to them would make conformance unachievable rather than
 * stricter.
 */

import { existsSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

import { siblingPath } from "./test-support/siblings.js";

/** Families this SDK covers, each naming the test that reads its vector. */
const ACCOUNTED_FOR: ReadonlyArray<readonly [string, string]> = [
  ["capacity-evidence", "src/artifacts/capacity-evidence.test.ts"],
  ["ccvp-consistency", "src/artifacts/context-snapshot.test.ts"],
  ["artifact-shape", "src/artifacts/artifact-shape.conformance.test.ts"],
  ["composite-m-prime", "src/crypto/composite.conformance.test.ts"],
  ["original-material", "src/artifacts/original-material.conformance.test.ts"],
  ["submission-set", "src/artifacts/original-material.conformance.test.ts"],
  ["submission-set-limits", "src/artifacts/artifact-shape.conformance.test.ts"],
  ["issuer-key-derivation", "src/artifacts/issuer-key-derivation.conformance.test.ts"],
  ["ecdsa-p256-deterministic", "src/crypto/ecdsa-p256-deterministic.conformance.test.ts"],
  ["collection-merkle", "src/crypto/collection-merkle.test.ts"],
  ["holder-keyset", "src/artifacts/holder-keyset.test.ts"],
  ["key-derivation", "src/crypto/key-derivation.conformance.test.ts"],
  ["pseudonym", "src/crypto/pseudonym.test.ts"],
  ["subject-ai-decision", "src/crypto/canonical-subject.test.ts"],
  ["subject-binary", "src/crypto/canonical-subject.test.ts"],
  ["subject-collection", "src/crypto/canonical-subject.test.ts"],
  ["subject-context-snapshot", "src/crypto/context-snapshot.conformance.test.ts"],
  ["subject-email", "src/crypto/canonical-subject.test.ts"],
  ["subject-text", "src/crypto/canonical-subject.test.ts"],
  ["strict-json", "src/crypto/strict-json.conformance.test.ts"],
] as const;

/**
 * Families in the contract that do not apply here, each with the reason.
 *
 * Entries marked `GAP:` are constructions this SDK DOES perform and does not yet
 * check. They are named rather than quietly absent: an acknowledged gap is a
 * task, an unlisted one is a surprise.
 */
const OUT_OF_SCOPE: ReadonlyArray<readonly [string, string]> = [
  ["independence-proof-signature", "composed and signed by the issuance service"],
  ["manifest-resolution", "resolution is the verifier's and the node's"],
  ["operator-receipt", "signed by a transporting node, not by an issuer SDK"],
  ["operator-domain-binding", "an SDK never signs or registers domain-binding statements: the node does"],
  ["rules-domain", "the domain table is consumed through the artifacts, not resolved here"],
  ["settlement-preimages", "assembled by the settlement side"],
  ["verification-package", "this SDK assembles the package from artifacts held to their own families and computes no package digest of its own"],
  ["composite-verification", "verifier-side: this SDK signs composites, it does not verify them"],
  ["level1-binding", "the issuer receives a signed binding and carries it verbatim into the evidence; it neither reconstructs its bytes nor verifies its signature, so there is nothing here to hold to the vector. It becomes in scope the day an SDK checks the binding it was handed"],
] as const;

/** The contract's `fixtures/primitives`, or null when it is not checked out. */
function primitivesDir(): string | null {
  const dir = siblingPath(
    import.meta.url,
    "certcrypt-conformance",
    "fixtures",
    "primitives"
  );
  return existsSync(dir) ? dir : null;
}

test("every claimed family exists in the contract", () => {
  const dir = primitivesDir();
  if (dir === null) return; // absence is reported by the sibling guard, loudly
  for (const [family, testFile] of ACCOUNTED_FOR) {
    assert.ok(
      existsSync(join(dir, family)),
      `this SDK claims to cover '${family}' (via ${testFile}), which the contract does ` +
        `not have — renamed or removed upstream, so the claim is now false`
    );
  }
});

test("every claimed test file exists", () => {
  // dist/src/<file>.js -> up 2 = this repo. Resolved from import.meta.url, never
  // from cwd, so it holds wherever npm test is run from.
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  for (const [family, testFile] of ACCOUNTED_FOR) {
    const path = join(repoRoot, testFile);
    assert.ok(
      existsSync(path),
      `'${family}' claims to be covered by ${testFile}, which does not exist — ` +
        `the coverage claim names nothing`
    );
  }
});

test("a family the contract grows must be classified, not ignored", () => {
  const dir = primitivesDir();
  if (dir === null) return;
  const classified = new Set([
    ...ACCOUNTED_FOR.map(([f]) => f),
    ...OUT_OF_SCOPE.map(([f]) => f),
  ]);
  const unclassified = readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((name) => !classified.has(name))
    .sort();
  assert.deepEqual(
    unclassified,
    [],
    `the contract carries families this SDK has not classified: ${JSON.stringify(unclassified)}. ` +
      `Add each to ACCOUNTED_FOR with the test that reads it, or to OUT_OF_SCOPE with the ` +
      `reason it does not apply. A family nobody classifies is a family nobody checks.`
  );
});

test("no family is both accounted for and out of scope", () => {
  const excused = new Set(OUT_OF_SCOPE.map(([f]) => f));
  for (const [family] of ACCOUNTED_FOR) {
    assert.ok(
      !excused.has(family),
      `'${family}' is both accounted for and out of scope — one of the two is wrong`
    );
  }
});

test("no gap is left unrecorded", () => {
  // Closing a gap means MOVING it to ACCOUNTED_FOR with a test that reads the
  // vector. This fails if someone deletes the entry instead, which would erase
  // the gap from the record without anything having been checked.
  // "GAP:" or "GAP (implementation):" — the second marks a gap that cannot be
  // closed by reading the vector, because the construction is not implemented
  // here at all. Both are gaps and both must stay on the record.
  const gaps = OUT_OF_SCOPE.filter(([, why]) => why.startsWith("GAP"))
    .map(([f]) => f)
    .sort();
  assert.deepEqual(
    gaps,
    [],
    "the recorded gaps changed: close one by moving it to ACCOUNTED_FOR, never by removing it"
  );
});
