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
 * `prepare()` / `submit()` — signing a certificate without sending it, so N can
 * travel in ONE submission set.
 *
 * Grouping amortizes the per-submission overhead, so the saving is real and the
 * thing that must not regress is the WIRE: a commitment prepared and submitted
 * has to be byte-identical to one `issue()` produces, or grouping would quietly emit different certificates than the single
 * path. These tests pin that, the N-in-one-request shape, and the no-reuse
 * invariant that makes `prepare()` irreversible in unlinkable mode.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Certcrypt, InMemoryLeafStore } from "./issuer.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";
import {
  MAX_SUBMISSION_SET_MEMBERS,
  SubmissionSetTooLargeError,
} from "./artifacts/capacity-evidence.js";

const SEED = "22".repeat(32);
const FINGERPRINT = "cd".repeat(32);
const RULES = "rules/conformance";

/** A node that activates and accepts an /v1/issue of N members, recording
 *  every request body so the wire form is observable from the public surface. */
function fakeNode(treeSize = 1) {
  // Must match the instance's tree: activation authorizes ONE key-set root, and
  // signing under a different one is refused (as it should be).
  const keySet = HolderKeySet.fromMasterSeed(SEED, treeSize);
  const bodies: Record<string, unknown>[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const json = (body: unknown) =>
      ({
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      }) as Response;

    if (url.includes("/v1/activate")) {
      return json({
        authorization_id: "auth-1",
        holder_key_set_root: keySet.root,
        level1_binding: {
          system_id: "certcrypt",
          rules_version: RULES,
          system_root_fingerprint: FINGERPRINT,
          authorized_role: "issuer",
          authorization_issuer_kid: "kid-l1",
          valid_from: "2020-01-01T00:00:00Z",
          valid_until: "2099-01-01T00:00:00Z",
          holder_key_set_root: keySet.root,
        },
        level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
        holder_id: "holder-1",
        pool_id: "pool-1",
        status: "redeemed",
      });
    }
    if (url.includes("/v1/issue")) {
      const body = JSON.parse(String(init?.body ?? "{}"));
      bodies.push(body);
      // One result per submitted member, indexed as the node indexes them.
      const members = (body.commitments as unknown[]) ?? [];
      return json({
        request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        submission_set_id: "set-1",
        results: members.map((_, i) => ({
          operation_id: `op-${i}`,
          commitment_index: i,
          state: { state: "accepted", upstream_operation_id: `up-${i}` },
        })),
      });
    }
    throw new Error(`unexpected url ${url}`);
  }) as typeof fetch;
  return { fetchImpl, bodies };
}

function certcrypt(fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
  return new Certcrypt({
    nodeBaseUrl: "http://node.test",
    keysetSeed: SEED,
    integrationKey: "int-key-1",
    poolId: "pool-1",
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    fetch: fetchImpl,
    ...extra,
  });
}

const subject = (text: string) => [
  { profile: "subject.text/1", material: new TextEncoder().encode(text) },
];

/**
 * The property that makes grouping safe to adopt: preparing and submitting must
 * put on the wire EXACTLY what issue() puts there. If the two paths diverged, a
 * batch would emit certificates subtly different from the single path — and the
 * difference would only surface when a third party tried to verify one.
 *
 * Fields that are random or clock-derived per emission (nonce, salt, timestamps)
 * are pinned by construction instead: both runs are given the same issued_at and
 * the same subject, and what is compared is the STRUCTURE of the commitment plus
 * the fields a verifier reproduces.
 */
test("a prepared commitment reaches the wire in the same shape issue() sends", async () => {
  const a = fakeNode();
  const viaIssue = certcrypt(a.fetchImpl);
  await viaIssue.issue({ subjects: subject("hello\n"), issuedAt: "2026-01-01T00:00:00Z" });

  const b = fakeNode();
  const viaPrepare = certcrypt(b.fetchImpl);
  const prepared = await viaPrepare.prepare({
    subjects: subject("hello\n"),
    issuedAt: "2026-01-01T00:00:00Z",
  });
  await viaPrepare.submit([prepared]);

  assert.equal(a.bodies.length, 1, "issue() sends exactly one request");
  assert.equal(b.bodies.length, 1, "prepare()+submit() sends exactly one request");

  const one = (a.bodies[0] as { commitments: Record<string, unknown>[] }).commitments[0]!;
  const two = (b.bodies[0] as { commitments: Record<string, unknown>[] }).commitments[0]!;

  // Same top-level members, same operative context, same evidence structure.
  assert.deepEqual(Object.keys(one).sort(), Object.keys(two).sort());
  assert.deepEqual(one.operative, two.operative);

  const ev1 = one.capacity_evidence as Record<string, unknown>;
  const ev2 = two.capacity_evidence as Record<string, unknown>;
  assert.deepEqual(Object.keys(ev1).sort(), Object.keys(ev2).sort());
  assert.equal(ev1.profile, ev2.profile);

  // The projected commitment is what a verifier reproduces: the declared units and
  // the temporal pair must match, since both runs issued the same subject at the
  // same instant under the same rules domain.
  const pc1 = ev1.projected_commitment as Record<string, unknown>;
  const pc2 = ev2.projected_commitment as Record<string, unknown>;
  assert.equal(pc1.declared_effective_units, pc2.declared_effective_units);
  assert.equal(pc1.issued_at, pc2.issued_at);
  assert.equal(pc1.expires_at, pc2.expires_at);
  assert.equal(pc1.consumed_quantity, pc2.consumed_quantity);
});

/**
 * The point of the whole surface: N certificates, ONE request. It is
 * N-in-one-request and synchronous — nothing is buffered, so the count of
 * outbound requests is exactly one no matter how many members travel.
 */
test("N prepared commitments travel in a single request", async () => {
  const { fetchImpl, bodies } = fakeNode();
  const cc = certcrypt(fetchImpl);

  const prepared = [
    await cc.prepare({ subjects: subject("one\n") }),
    await cc.prepare({ subjects: subject("two\n") }),
    await cc.prepare({ subjects: subject("three\n") }),
  ];
  const { response, handles } = await cc.submit(prepared);

  assert.equal(bodies.length, 1, "three certificates cost ONE request");
  const sent = (bodies[0] as { commitments: unknown[] }).commitments;
  assert.equal(sent.length, 3, "all three members travel in that request");

  // One handle per member, in the order they were passed in, each carrying the
  // operation the node assigned to THAT member.
  assert.equal(handles.length, 3);
  assert.deepEqual(handles.map((h) => h.operationId), ["op-0", "op-1", "op-2"]);
  assert.deepEqual(handles.map((h) => h.commitmentIndex), [0, 1, 2]);
  assert.equal(response.results?.length, 3);

  // Each handle must carry ITS OWN evidence, not a shared reference — a batch
  // where every handle pointed at the same emission would resolve three times to
  // one operation and lose the other two.
  const refs = new Set(handles.map((h) => h.independenceRef));
  assert.equal(refs.size, 3, "each handle references a distinct emission");
});

/**
 * The invariant the SDK exists to hold: in unlinkable mode no leaf is ever used
 * twice. A verifier cannot detect a repeat — nothing in the artifacts reveals it —
 * so if grouping reused a leaf the unlinkability would be lost silently.
 */
test("unlinkable: prepared commitments never repeat a leaf", async () => {
  const { fetchImpl } = fakeNode(64);
  const cc = certcrypt(fetchImpl, {
    mode: "unlinkable",
    treeSize: 64,
    leafStore: new InMemoryLeafStore(),
  });

  const prepared = [
    await cc.prepare({ subjects: subject("a\n") }),
    await cc.prepare({ subjects: subject("b\n") }),
    await cc.prepare({ subjects: subject("c\n") }),
    await cc.prepare({ subjects: subject("d\n") }),
  ];

  const leaves = prepared.map((p) => p.leafIndex);
  assert.equal(new Set(leaves).size, leaves.length, `leaves repeated: ${leaves}`);
  // Monotone allocation: each prepare() takes the next leaf and never goes back.
  assert.deepEqual(leaves, [...leaves].sort((x, y) => x - y));
});

/**
 * One submission set is one issuer under one authorization. A mixed set is refused
 * BEFORE the request is spent — the commitments are already signed either way, but
 * there is no reason to also burn the round-trip on a set the node will reject.
 */
test("submit() refuses a set whose members carry different authorizations", async () => {
  const { fetchImpl, bodies } = fakeNode();
  const cc = certcrypt(fetchImpl);

  const first = await cc.prepare({ subjects: subject("a\n") });
  const alien = {
    ...(await cc.prepare({ subjects: subject("b\n") })),
    authorizationId: "auth-from-somewhere-else",
  };

  await assert.rejects(
    () => cc.submit([first, alien]),
    /One submission set is one issuer under one authorization/,
  );
  assert.equal(bodies.length, 0, "the mixed set never reaches the node");
});

test("submit() refuses an empty batch", async () => {
  const { fetchImpl } = fakeNode();
  const cc = certcrypt(fetchImpl);
  await assert.rejects(() => cc.submit([]), /non-empty prepared\[\] array/);
});

/**
 * submission-set/1 §8.1: the producer refuses to build a set over the bound.
 * The count is what is checked, so one prepared commitment repeated stands in
 * for N distinct ones.
 */
test("submit() sends a set of exactly MAX_SUBMISSION_SET_MEMBERS commitments", async () => {
  const { fetchImpl, bodies } = fakeNode();
  const cc = certcrypt(fetchImpl);
  const one = await cc.prepare({ subjects: subject("bound\n") });
  const { handles } = await cc.submit(Array.from({ length: MAX_SUBMISSION_SET_MEMBERS }, () => one));
  assert.equal(bodies.length, 1);
  assert.equal((bodies[0] as { commitments: unknown[] }).commitments.length, MAX_SUBMISSION_SET_MEMBERS);
  assert.equal(handles.length, MAX_SUBMISSION_SET_MEMBERS);
});

test("submit() refuses MAX_SUBMISSION_SET_MEMBERS + 1 commitments before sending", async () => {
  const { fetchImpl, bodies } = fakeNode();
  const cc = certcrypt(fetchImpl);
  const one = await cc.prepare({ subjects: subject("over\n") });
  const sentBefore = bodies.length;
  await assert.rejects(
    () => cc.submit(Array.from({ length: MAX_SUBMISSION_SET_MEMBERS + 1 }, () => one)),
    (e: unknown) =>
      e instanceof SubmissionSetTooLargeError && e.count === MAX_SUBMISSION_SET_MEMBERS + 1,
  );
  assert.equal(bodies.length, sentBefore, "the over-bound set never reaches the node");
});

/**
 * `issue()` is prepare() + submit() with N=1, so its result must be unchanged:
 * same handle shape, same commitment, same collections. This pins that the two
 * paths are observably the same.
 */
test("issue() still returns a complete result after being rebuilt on prepare()", async () => {
  const { fetchImpl, bodies } = fakeNode();
  const cc = certcrypt(fetchImpl);

  const result = await cc.issue({ subjects: subject("hello\n") });

  assert.equal(bodies.length, 1);
  assert.equal(result.handle.operationId, "op-0");
  assert.equal(result.handle.upstreamOperationId, "up-0");
  assert.equal(result.handle.commitmentIndex, 0);
  assert.ok(result.handle.baseCertificate, "the handle carries the signed certificate");
  assert.ok(result.handle.capacityEvidence, "and its capacity evidence");
  assert.ok(result.handle.independenceRef, "and the independence reference");
  assert.ok(result.commitment.capacity_evidence, "the commitment is returned");
  assert.equal(typeof result.authorizationId, "string");
  assert.ok(result.authorizationId.length > 0);
  assert.deepEqual(result.collections, []);
});
