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
 * Golden-vector parity for issuer-side `canonicalBytesForSubject` against the
 * cross-language conformance fixtures. If any of these diverge by one byte, the
 * CCCP/1 subject commitment the SDK mints will not match what the verifier
 * recomputes from the original material.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { siblingPath, missingSibling } from "../test-support/siblings.js";
import {
  canonicalBytesForSubject,
  SUBJECT_BINARY,
  SUBJECT_TEXT,
  SUBJECT_EMAIL,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
  UnsupportedProfileError,
} from "./canonical-subject.js";

const FIXTURES = siblingPath(
  import.meta.url,
  "certcrypt-conformance",
  "fixtures",
  "primitives"
);
const skip = missingSibling(
  import.meta.url,
  "certcrypt-conformance",
  "fixtures",
  "primitives"
);

function loadVectors(profileDir: string): any {
  return JSON.parse(
    readFileSync(resolve(FIXTURES, profileDir, "vectors.json"), "utf-8")
  );
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function sha3_256Hex(bytes: Uint8Array): string {
  return createHash("sha3-256").update(bytes).digest("hex");
}

test("subject.binary/1: canonical_bytes == identity, digest matches vectors", {skip}, () => {
  const vectors = loadVectors("subject-binary").vectors;
  for (const v of vectors) {
    const input = hexToBytes(v.input_hex);
    const canonical = canonicalBytesForSubject(SUBJECT_BINARY, input);
    assert.equal(toHex(canonical), v.input_hex, `${v.name}: identity`);
    assert.equal(
      sha3_256Hex(canonical),
      v.subject_local_digest_hex,
      `${v.name}: subject_local_digest`
    );
  }
});

test("subject.text/1: canonical_hex + digest match vectors", {skip}, () => {
  const vectors = loadVectors("subject-text").vectors;
  for (const v of vectors) {
    const input = hexToBytes(v.input_hex);
    const canonical = canonicalBytesForSubject(SUBJECT_TEXT, input);
    assert.equal(toHex(canonical), v.canonical_hex, `${v.name}: canonical_hex`);
    assert.equal(
      sha3_256Hex(canonical),
      v.subject_local_digest_hex,
      `${v.name}: subject_local_digest`
    );
  }
});

test("subject.email/1: canonical_hex + digest match vectors", {skip}, () => {
  const vectors = loadVectors("subject-email").vectors;
  for (const v of vectors) {
    const input = hexToBytes(v.input_hex);
    const canonical = canonicalBytesForSubject(SUBJECT_EMAIL, input);
    assert.equal(toHex(canonical), v.canonical_hex, `${v.name}: canonical_hex`);
    assert.equal(
      sha3_256Hex(canonical),
      v.subject_local_digest_hex,
      `${v.name}: subject_local_digest`
    );
  }
});

test("subject.collection/1: JCS canonical + digest match vectors", {skip}, () => {
  const vectors = loadVectors("subject-collection").vectors;
  for (const v of vectors) {
    // The subject is a JSON object; the SDK receives its JSON source bytes.
    const material = new TextEncoder().encode(JSON.stringify(v.collection_subject));
    const canonical = canonicalBytesForSubject(SUBJECT_COLLECTION, material);
    assert.equal(
      new TextDecoder().decode(canonical),
      v.expected_canonical_utf8,
      `${v.name}: canonical utf8`
    );
    assert.equal(
      sha3_256Hex(canonical),
      v.expected_subject_local_digest_hex,
      `${v.name}: subject_local_digest`
    );
  }
});

test("subject.ai-decision/1: JCS canonical + digest match vectors", {skip}, () => {
  const vectors = loadVectors("subject-ai-decision").vectors;
  for (const v of vectors) {
    const material = new TextEncoder().encode(JSON.stringify(v.decision_record));
    const canonical = canonicalBytesForSubject(SUBJECT_AI_DECISION, material);
    assert.equal(
      new TextDecoder().decode(canonical),
      v.expected_canonical_utf8,
      `${v.name}: canonical utf8`
    );
    assert.equal(
      sha3_256Hex(canonical),
      v.expected_subject_local_digest_hex,
      `${v.name}: subject_local_digest`
    );
  }
});

test("subject.ai-decision/1: a UTF-8 BOM fails closed", () => {
  const record = new TextEncoder().encode(JSON.stringify({ profile: SUBJECT_AI_DECISION }));
  const material = Uint8Array.from([0xef, 0xbb, 0xbf, ...record]);
  assert.throws(
    () => canonicalBytesForSubject(SUBJECT_AI_DECISION, material),
    /must not begin with a UTF-8 BOM/,
  );
});

test("unsupported profile fails closed", () => {
  assert.throws(
    () => canonicalBytesForSubject("subject.unknown/1", new Uint8Array(0)),
    UnsupportedProfileError
  );
});
