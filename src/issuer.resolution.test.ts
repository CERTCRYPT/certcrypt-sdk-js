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
 * What the issuer does with what it learned and with what it is told later:
 * the pool activation hands back, the terminal states a resolution can end in,
 * the verification context a package records, and the recovery read a process
 * that never emitted still has to authenticate.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Certcrypt, readMessage, type EmissionHandle } from "./issuer.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";

const SEED = "11".repeat(32);
const FINGERPRINT = "ab".repeat(32);
const RULES = "rules/conformance";
const keySetRoot = HolderKeySet.fromMasterSeed(SEED, 1).root;
const BINDING = {
  level1_binding: {
    system_id: "certcrypt",
    rules_version: RULES,
    system_root_fingerprint: FINGERPRINT,
    authorized_role: "issuer",
    authorization_issuer_kid: "kid-l1",
    valid_from: "2020-01-01T00:00:00Z",
    valid_until: "2099-01-01T00:00:00Z",
    holder_key_set_root: keySetRoot,
  },
  level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
};

/** A node routed by path; records every call in order. */
function fakeNode(routes: Record<string, (url: string, init?: RequestInit) => { status: number; body: unknown }>) {
  const calls: Array<{ url: string; headers: Record<string, string>; body: unknown }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({
      url,
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body ? JSON.parse(String(init.body)) : null,
    });
    const key = Object.keys(routes).find((k) => url.includes(k));
    if (!key) throw new Error(`unexpected url ${url}`);
    const { status, body } = routes[key]!(url, init);
    const text = JSON.stringify(body);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => text,
    } as Response;
  }) as typeof fetch;
  return { fetchImpl, calls };
}

const ACTIVATE = () => ({
  status: 200,
  body: {
    ...BINDING,
    holder_id: "holder-1",
    pool_id: "pool-learned",
    status: "redeemed",
  },
});

/** An issuer already holding a binding, so resolution needs no activation call. */
function boundIssuer(fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
  return new Certcrypt({
    nodeBaseUrl: "http://node.test",
    keysetSeed: SEED,
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    poolId: "pool-1",
    holderId: "holder-1",
    signedLevel1: BINDING as never,
    fetch: fetchImpl,
    ...extra,
  });
}

const HANDLE: EmissionHandle = {
  operationId: "op-1",
  independenceRef: "ab".repeat(32),
  commitmentIndex: 0,
  capacityEvidence: { profile: "zero-data.unlinkable" },
  baseCertificate: { schema: "certcrypt-certificate" },
};

function readyBody() {
  const proof = { consumed_commitment_ids: ["c-1", "c-2"], subtree_root: "cd".repeat(32) };
  return {
    operation_id: "op-1",
    state: { state: "independent_ready" },
    independence_proof: Buffer.from(JSON.stringify(proof)).toString("base64"),
    settlement_material: Buffer.from('{"settlement_profile_id":"x"}').toString("base64"),
  };
}

// --- the pool activation hands back ----------------------------------------------

test("a pool learned at activation reaches the commitment when none is configured", async () => {
  const { fetchImpl, calls } = fakeNode({
    "/v1/activate": ACTIVATE,
    "/v1/issue": () => ({
      status: 200,
      body: {
        request_id: "R",
        submission_set_id: "S",
        results: [{ operation_id: "op-1", commitment_index: 0, state: { state: "accepted" } }],
      },
    }),
  });
  const issuer = new Certcrypt({
    nodeBaseUrl: "http://node.test",
    keysetSeed: SEED,
    integrationKey: "int-key-1",
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    fetch: fetchImpl,
  });
  const res = await issuer.issue({
    subjects: [{ profile: "subject.text/1", material: new TextEncoder().encode("hello\n") }],
  });
  assert.deepEqual(res.commitment.operative, { holder_id: "holder-1", pool_id: "pool-learned" });
  const sent = calls.find((c) => c.url.includes("/v1/issue"))!.body as {
    commitments: Array<{ operative: { pool_id: string } }>;
  };
  assert.equal(sent.commitments[0]!.operative.pool_id, "pool-learned");
});

// --- terminal states ------------------------------------------------------------------

for (const terminal of [
  "rejected",
  "insufficient_capacity",
  "replay_detected",
  "pre_evaluation_rejected",
  "submission_failed",
]) {
  test(`resolveEmission reports ${terminal} as rejected`, async () => {
    const { fetchImpl } = fakeNode({
      "/v1/operations/": () => ({ status: 200, body: { operation_id: "op-1", state: { state: terminal } } }),
    });
    const res = await boundIssuer(fetchImpl).resolveEmission(HANDLE);
    assert.deepEqual(res, { state: "rejected", nodeState: terminal });
  });
}

test("resolveEmission reports expired as expired, with its reason", async () => {
  const { fetchImpl } = fakeNode({
    "/v1/operations/": () => ({
      status: 200,
      body: { operation_id: "op-1", state: { state: "expired", reason_code: "commitment_window_expired" } },
    }),
  });
  const res = await boundIssuer(fetchImpl).resolveEmission(HANDLE);
  assert.deepEqual(res, {
    state: "expired",
    nodeState: "expired",
    reasonCode: "commitment_window_expired",
  });
});

test("resolveEmission by commitment reports insufficient_capacity as rejected", async () => {
  const { fetchImpl } = fakeNode({
    "/v1/operations/": () => ({ status: 404, body: { error: "not_found" } }),
    "/v1/emissions/by-commitment/": () => ({
      status: 200,
      body: { operation_id: "op-1", status: "insufficient_capacity" },
    }),
  });
  const res = await boundIssuer(fetchImpl).resolveEmission(HANDLE);
  assert.deepEqual(res, { state: "rejected", nodeState: "insufficient_capacity" });
});

test("a wait that ends without a terminal state resolves as pending, not as an error", async () => {
  const { fetchImpl } = fakeNode({
    "/v1/operations/": () => ({ status: 200, body: { operation_id: "op-1", state: { state: "processing" } } }),
  });
  const res = await boundIssuer(fetchImpl).resolveEmission(HANDLE, {
    wait: { intervalMs: 1, maxAttempts: 2 },
  });
  assert.equal(res.state, "pending");
});

// --- the verification context the package records -----------------------------------

test("the package records this instance's rules_version and system_id by default", async () => {
  const { fetchImpl } = fakeNode({ "/v1/operations/": () => ({ status: 200, body: readyBody() }) });
  const res = await boundIssuer(fetchImpl).resolveEmission(HANDLE);
  assert.equal(res.state, "independent");
  assert.deepEqual(
    (res as { verificationPackage: { verification_context: unknown } }).verificationPackage
      .verification_context,
    { rules_version: RULES, system_id: "certcrypt" }
  );
});

test("an explicit verification context wins over the instance's", async () => {
  const { fetchImpl } = fakeNode({ "/v1/operations/": () => ({ status: 200, body: readyBody() }) });
  const ctx = { rules_version: "rules/2026-01", system_id: "other" };
  const res = await boundIssuer(fetchImpl).resolveEmission(HANDLE, { verificationContext: ctx });
  assert.deepEqual(
    (res as { verificationPackage: { verification_context: unknown } }).verificationPackage
      .verification_context,
    ctx
  );
});

// --- recovery reads activate first --------------------------------------------------

test("listUnresolvedEmissions activates before reading, so the read is signed", async () => {
  const { fetchImpl, calls } = fakeNode({
    "/v1/activate": ACTIVATE,
    "/v1/emissions/unresolved": () => ({ status: 200, body: { emissions: [], truncated: false } }),
  });
  const issuer = new Certcrypt({
    nodeBaseUrl: "http://node.test",
    keysetSeed: SEED,
    integrationKey: "int-key-1",
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    fetch: fetchImpl,
  });
  const page = await issuer.listUnresolvedEmissions("2026-01-01T00:00:00Z");
  assert.deepEqual(page, { emissions: [], truncated: false });
  assert.deepEqual(
    calls.map((c) => new URL(c.url).pathname),
    ["/v1/activate", "/v1/emissions/unresolved"]
  );
  assert.ok(calls[1]!.headers["x-certcrypt-issuer-read"], "the read must carry the issuer's half");
});

test("every read carries its own single-use challenge, signed with the resource", async () => {
  // Each read mints a `<millis>.<random>` challenge that the issuance service
  // accepts once, so the node that relays the half cannot keep it and read again
  // on its own.
  const { fetchImpl, calls } = fakeNode({
    "/v1/activate": ACTIVATE,
    "/v1/emissions/unresolved": () => ({ status: 200, body: { emissions: [], truncated: false } }),
  });
  const issuer = new Certcrypt({
    nodeBaseUrl: "http://node.test",
    keysetSeed: SEED,
    integrationKey: "int-key-1",
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    fetch: fetchImpl,
  });
  await issuer.listUnresolvedEmissions("2026-01-01T00:00:00Z");
  await issuer.listUnresolvedEmissions("2026-01-01T00:00:00Z");
  const halves = calls
    .filter((c) => new URL(c.url).pathname === "/v1/emissions/unresolved")
    .map((c) => JSON.parse(Buffer.from(c.headers["x-certcrypt-issuer-read"]!, "base64").toString("utf8")));
  assert.equal(halves.length, 2);
  for (const h of halves) {
    assert.match(h.challenge, /^\d{13}\.[A-Za-z0-9+/=]{16,}$/);
    assert.ok(Math.abs(Number(h.challenge.split(".")[0]) - Date.now()) < 60_000);
  }
  assert.notEqual(halves[0].challenge, halves[1].challenge, "a challenge is never reused");
  assert.equal(
    readMessage(halves[0].challenge, "emissions:unresolved:2026-01-01T00:00:00Z"),
    `certcrypt:read:2|${halves[0].challenge}|emissions:unresolved:2026-01-01T00:00:00Z`
  );
});
