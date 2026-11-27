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
 * The guards an issuer meets before anything is signed: what construction
 * refuses, the order `prepare()` checks things in, and what counts as "not
 * given" for an optional value — an absent one falls back, an explicit one is
 * used as given, including 0 and the empty string.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Certcrypt, InMemoryLeafStore } from "./issuer.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";

const SEED = "22".repeat(32);
const RULES = "rules/conformance";
const FINGERPRINT = "ab".repeat(32);
const KEY_SET_ROOT = HolderKeySet.fromMasterSeed(SEED, 1).root;

const unreachableFetch = (async () => {
  throw new Error("no request should leave the process for a guard");
}) as typeof fetch;

function opts(extra: Record<string, unknown> = {}) {
  return {
    nodeBaseUrl: "http://node.test",
    fetch: unreachableFetch,
    keysetSeed: SEED,
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    poolId: "pool-1",
    holderId: "holder-1",
    signedLevel1: {
      level1_binding: {
        system_id: "certcrypt",
        rules_version: RULES,
        system_root_fingerprint: FINGERPRINT,
        authorized_role: "issuer",
        authorization_issuer_kid: "kid-l1",
        valid_from: "2020-01-01T00:00:00Z",
        valid_until: "2099-01-01T00:00:00Z",
        holder_key_set_root: KEY_SET_ROOT,
      },
      level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
    },
    ...extra,
  } as never;
}

/** A bound issuer, so `prepare()` runs locally. */
function boundIssuer(extra: Record<string, unknown> = {}) {
  return new Certcrypt(opts(extra));
}

/** The signed projected commitment the evidence carries. */
function projected(prepared: { commitment: { capacity_evidence: unknown } }) {
  return (prepared.commitment.capacity_evidence as {
    projected_commitment: { declared_effective_units: string; issued_at: string; expires_at: string };
  }).projected_commitment;
}

const SUBJECTS = [{ profile: "subject.text/1", material: new TextEncoder().encode("hello\n") }];

// --- construction ---------------------------------------------------------------

test("unlinkable mode refuses a tree of one leaf, with the shared message", () => {
  assert.throws(
    () => new Certcrypt(opts({ mode: "unlinkable", treeSize: 1, leafStore: new InMemoryLeafStore() })),
    (e: unknown) =>
      e instanceof Error &&
      e.message === "unlinkable mode needs a treeSize >= 2 (a distinct leaf per cert)"
  );
});

test("unlinkable mode refuses construction without a leaf store, naming it", () => {
  assert.throws(
    () => new Certcrypt(opts({ mode: "unlinkable", treeSize: 4 })),
    /requires a leafStore: each commitment must be signed with a leaf never used before/
  );
});

for (const ttl of [0, -1, 1.5]) {
  test(`a commitment TTL of ${ttl} is refused at construction`, () => {
    assert.throws(
      () => new Certcrypt(opts({ commitmentTtlSeconds: ttl })),
      /must be a positive whole number of seconds/
    );
  });
}

test("the retry options set on Certcrypt reach the node client, base and cap included", () => {
  const issuer = new Certcrypt(
    opts({ retry: { maxElapsedMs: 15_000, maxAttempts: 3, baseMs: 50, capMs: 2_000 } })
  );
  const policy = (issuer.nodeClient() as unknown as { retryPolicy: Record<string, unknown> }).retryPolicy;
  assert.deepEqual(
    { ...policy },
    { maxElapsedMs: 15_000, maxAttempts: 3, backoffBaseMs: 50, backoffCapMs: 2_000 }
  );
});

// --- the order prepare() checks things in ----------------------------------------

test("prepare checks the pool before anything about the input", async () => {
  const issuer = boundIssuer({ poolId: undefined });
  await assert.rejects(issuer.prepare({ subjects: [] }), /^Error: no pool_id/);
});

test("prepare checks the holder before the system configuration", async () => {
  const issuer = boundIssuer({ holderId: undefined, systemId: undefined });
  await assert.rejects(issuer.prepare({ subjects: [] }), /^Error: no holder_id/);
});

test("prepare checks the system id before the subjects", async () => {
  const issuer = boundIssuer({ systemId: undefined });
  await assert.rejects(issuer.prepare({ subjects: [] }), /requires systemId/);
});

// --- absent falls back, explicit is used as given --------------------------------

test("an explicit declared_effective_units of 0 is used as given", async () => {
  const prepared = await boundIssuer().prepare({ subjects: SUBJECTS, declaredEffectiveUnits: "0" });
  assert.equal(
    projected(prepared).declared_effective_units,
    "0"
  );
});

test("an explicit empty declared_effective_units is used as given, not replaced", async () => {
  const prepared = await boundIssuer().prepare({ subjects: SUBJECTS, declaredEffectiveUnits: "" });
  assert.equal(
    projected(prepared).declared_effective_units,
    ""
  );
});

test("an absent declared_effective_units is the subjects' sum", async () => {
  const prepared = await boundIssuer().prepare({ subjects: [...SUBJECTS, ...SUBJECTS] });
  assert.equal(
    projected(prepared).declared_effective_units,
    "2"
  );
});

test("an explicit empty issued_at is refused, not replaced by the clock", async () => {
  await assert.rejects(boundIssuer().prepare({ subjects: SUBJECTS, issuedAt: "" }));
});

test("an explicit issued_at and the TTL fix expires_at", async () => {
  const prepared = await boundIssuer({ commitmentTtlSeconds: 60 }).prepare({
    subjects: SUBJECTS,
    issuedAt: "2026-08-16T12:00:00Z",
  });
  const ev = projected(prepared);
  assert.deepEqual([ev.issued_at, ev.expires_at], ["2026-08-16T12:00:00Z", "2026-08-16T12:01:00Z"]);
});
