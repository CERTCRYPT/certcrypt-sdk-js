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
import { derivePseudonym, type PseudonymDomain } from "./pseudonym.js";
import { siblingPath, missingSibling } from "../test-support/siblings.js";

const FIXTURE = ["fixtures", "primitives", "pseudonym", "vectors.json"];
const VECTORS_PATH = siblingPath(import.meta.url, "certcrypt-conformance", ...FIXTURE);
const skip = missingSibling(import.meta.url, "certcrypt-conformance", ...FIXTURE);

interface PseudonymVector {
  name: string;
  operation_salt_utf8: string;
  domain: PseudonymDomain;
  stable_id: string;
  expected_pseudonym_hex: string;
}

interface PseudonymVectors {
  vectors: PseudonymVector[];
}

function loadVectors(): PseudonymVectors {
  return JSON.parse(readFileSync(VECTORS_PATH, "utf-8")) as PseudonymVectors;
}

test("CONFORMANCE: every pseudonym vector reproduces byte-for-byte", {skip}, () => {
  const { vectors } = loadVectors();
  assert.ok(vectors.length > 0, "fixture must carry vectors");
  for (const v of vectors) {
    const got = derivePseudonym(
      new TextEncoder().encode(v.operation_salt_utf8),
      v.domain,
      v.stable_id
    );
    assert.equal(
      got,
      v.expected_pseudonym_hex,
      `vector ${v.name}: pseudonym diverged from conformance vector`
    );
  }
});

test("framing: (salt=ab, id=c) and (salt=a, id=bc) do not collide", () => {
  const ab_c = derivePseudonym(new TextEncoder().encode("ab"), "holder", "c");
  const a_bc = derivePseudonym(new TextEncoder().encode("a"), "holder", "bc");
  assert.notEqual(ab_c, a_bc);
});

test("different salt -> unrelated pseudonym for the same id", () => {
  const s1 = derivePseudonym(new TextEncoder().encode("salt-1"), "holder", "holder:x");
  const s2 = derivePseudonym(new TextEncoder().encode("salt-2"), "holder", "holder:x");
  assert.notEqual(s1, s2);
});

test("domain separation: same salt+id, different domain -> different pseudonym", () => {
  const salt = new TextEncoder().encode("salt-1");
  const asHolder = derivePseudonym(salt, "holder", "x");
  const asPool = derivePseudonym(salt, "pool", "x");
  assert.notEqual(asHolder, asPool);
});
