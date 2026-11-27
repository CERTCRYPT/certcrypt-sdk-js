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
 * Strict JSON parsing, against the contract (`strict-json`): which documents
 * parse, which are refused, and which JSON subject materials are refused before
 * canonicalization. A material a verifier refuses must never reach a
 * commitment this SDK signs.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { strictJsonParse, StrictJsonError } from "./strict-json.js";
import { canonicalBytesForSubject } from "./canonical-subject.js";
import { siblingPath } from "../test-support/siblings.js";

function vectors(): any | null {
  const path = join(
    siblingPath(import.meta.url, "certcrypt-conformance", "fixtures", "primitives"),
    "strict-json",
    "vectors.json"
  );
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

test("strict-json: every case parses or is refused as the contract declares", () => {
  const v = vectors();
  if (v === null) return; // the sibling guard reports absence, loudly
  for (const c of v.cases) {
    let got: string;
    try {
      strictJsonParse(c.json_text);
      got = "ACCEPT";
    } catch (e) {
      assert.ok(e instanceof StrictJsonError, `case '${c.name}' threw something else`);
      got = "REJECTED";
    }
    assert.equal(got, c.expected, `strict-json case '${c.name}'`);
  }
});

test("strict-json: JSON subject material with a repeated member never canonicalizes", () => {
  const v = vectors();
  if (v === null) return;
  for (const c of v.profile_material_cases) {
    let got: string;
    try {
      canonicalBytesForSubject(c.profile, new TextEncoder().encode(c.material_utf8));
      got = "ACCEPT";
    } catch {
      got = "REJECTED";
    }
    assert.equal(got, c.expected_outcome, `material case '${c.name}'`);
  }
});
