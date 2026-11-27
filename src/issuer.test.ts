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
 * `Certcrypt.issue()` against a fake node.
 *
 * For the issuer the node is a transport: the SDK activates through it and hands
 * it the submission set, and asks it for nothing else. These tests pin that
 * contract and the wire form of what `issue()` sends.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Certcrypt } from "./issuer.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";

const SEED = "11".repeat(32);

const FINGERPRINT = "ab".repeat(32);
const RULES = "rules/conformance";

/**
 * A node that activates and accepts an issuance, counting every request by
 * route. Any other route is a test failure: the SDK has no business there.
 */
function fakeNode() {
  const calls = { activate: 0, issue: 0 };
  // The request body of the last /v1/issue — the only place a wire-format
  // regression is observable from the high-level surface.
  const bodies: { issue: Record<string, unknown> | null } = { issue: null };
  const keySet = HolderKeySet.fromMasterSeed(SEED, 1);
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const json = (body: unknown) =>
      ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) }) as Response;

    if (url.includes("/v1/activate")) {
      calls.activate++;
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
      calls.issue++;
      bodies.issue = JSON.parse(String(init?.body ?? "{}"));
      return json({
        request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        submission_set_id: "set-1",
        results: [
          {
            operation_id: "op-1",
            commitment_index: 0,
            state: { state: "accepted", upstream_operation_id: "up-1" },
          },
        ],
      });
    }
    throw new Error(`unexpected url ${url}`);
  }) as typeof fetch;
  return { fetchImpl, calls, bodies };
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

const SUBJECTS = [
  { profile: "subject.text/1", material: new TextEncoder().encode("hello\n") },
];

/**
 * A missing `systemId` must not default to "", which signs cleanly and is then
 * REJECTED by every conformant verifier on BASE_CERTIFICATE_STRUCTURE_VALID — a
 * failure that only surfaces at verification, in the recipient's hands. It is
 * required for ISSUED too, not just Independent, so there is no configuration in
 * which the empty default produces a usable certificate.
 */
test("issue() refuses to mint a certificate with no systemId", async () => {
  const { fetchImpl } = fakeNode();
  const issuer = certcrypt(fetchImpl, { systemId: undefined });
  await assert.rejects(
    () => issuer.issue({ subjects: SUBJECTS }),
    /systemId/,
    "an empty system_id must fail at issuance, not at verification"
  );
});

test("issue() asks the node for nothing but activation and the issuance", async () => {
  // Any other request throws in the fake, so reaching the assertions means the
  // node was used purely as a transport.
  const { fetchImpl, calls } = fakeNode();
  const res = await certcrypt(fetchImpl).issue({ subjects: SUBJECTS });
  assert.deepEqual(calls, { activate: 1, issue: 1 });
  assert.equal(res.handle.operationId, "op-1");
});

test("a bindingStore entry is the binding and its two identifiers, and a restart reuses it", async () => {
  let saved: unknown = null;
  const store = {
    load: async () => saved as never,
    save: async (e: unknown) => {
      saved = e;
    },
  };

  const first = fakeNode();
  await certcrypt(first.fetchImpl, { bindingStore: store }).issue({ subjects: SUBJECTS });
  assert.deepEqual(Object.keys(saved as object).sort(), ["binding", "holderId", "poolId"]);

  // A second process: the store hits, so activation never runs.
  const second = fakeNode();
  await certcrypt(second.fetchImpl, { bindingStore: store }).issue({ subjects: SUBJECTS });
  assert.deepEqual(second.calls, { activate: 0, issue: 1 });
});

/**
 * The elected window reaches the node only through the client's minting path, so
 * this pins that it survives the high-level `issue()`. The failure it guards
 * against is silent: a preference accepted but never forwarded, or forwarded with
 * camelCased keys, leaves an issuer electing a slower window on the default profile
 * with no error anywhere. Pin BOTH halves: that it is forwarded at all, and that
 * it is snake_case on the wire (the node's settlement preferences use the field
 * names verbatim).
 */
test("issue() forwards the elected settlement window snake_cased on the wire", async () => {
  const { fetchImpl, bodies } = fakeNode();

  await certcrypt(fetchImpl).issue({
    subjects: SUBJECTS,
    settlementPreferences: { windowProfile: "close_6h", fallbackPolicy: "slower_allowed" },
  });

  assert.deepEqual(
    (bodies.issue as { settlement_preferences?: unknown } | null)?.settlement_preferences,
    { window_profile: "close_6h", fallback_policy: "slower_allowed" },
    "the elected window must reach the wire snake_cased, or the node ignores it"
  );
});

test("issue() omits settlement_preferences entirely when none is elected", async () => {
  const { fetchImpl, bodies } = fakeNode();
  await certcrypt(fetchImpl).issue({ subjects: SUBJECTS });
  assert.ok(
    !("settlement_preferences" in (bodies.issue ?? {})),
    "an absent preference must not become a key the node has to interpret"
  );
});

test("the retry budget set on the issuer reaches the node client", () => {
  const sdk = certcrypt((async () => {
    throw new Error("no network in this test");
  }) as typeof fetch, { retry: { maxElapsedMs: 15_000, maxAttempts: 3 } });
  // A caller with a tight deadline sets a short budget; the option has to
  // arrive where retrying happens.
  const policy = (sdk.nodeClient() as unknown as { retryPolicy: Record<string, unknown> })
    .retryPolicy;
  assert.equal(policy.maxElapsedMs, 15_000);
  assert.equal(policy.maxAttempts, 3);
});
