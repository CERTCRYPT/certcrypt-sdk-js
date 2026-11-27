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
import { CertcryptNodeClient, CertcryptNodeError } from "./client.js";
import {
  MAX_SUBMISSION_SET_MEMBERS,
  SubmissionSetTooLargeError,
  ZERO_DATA_PROFILE,
} from "./artifacts/capacity-evidence.js";

/** Build a fake fetch that routes by URL/method to canned responses. */
function fakeFetch(
  routes: (url: string, init?: RequestInit) => { status: number; body: unknown }
): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const { status, body } = routes(url, init);
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => JSON.parse(text),
      text: async () => text,
    } as Response;
  }) as typeof fetch;
}

const COMMITMENTS = [
  {
    capacity_evidence: { profile: ZERO_DATA_PROFILE },
    operative: { holder_id: "h-1", pool_id: "p-1" },
  },
];

test("issue submits the submission set with issuer-auth and returns processing state", async () => {
  let sawBody: unknown = null;
  let sawHeaders: Record<string, string> = {};
  let proofsBuilt = 0;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test/",
    issuerAuthProof: () => `proof-${++proofsBuilt}`,
    fetch: fakeFetch((url, init) => {
      assert.ok(url.endsWith("/v1/issue"), `unexpected url ${url}`);
      assert.equal(init?.method, "POST");
      sawHeaders = init?.headers as Record<string, string>;
      sawBody = JSON.parse(init!.body as string);
      return {
        status: 200,
        body: {
          request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
          submission_set_id: "set-abc",
          results: [
            {
              operation_id: "op_X",
              commitment_index: 0,
              state: { state: "accepted", upstream_operation_id: "OP-UP" },
            },
          ],
        },
      };
    }),
  });

  const res = await client.issueCommitments(COMMITMENTS);
  assert.equal(res.results[0].operation_id, "op_X");
  assert.equal(res.results[0].state.state, "accepted");
  // The loose commitments were passed through verbatim (the node builds the set).
  assert.deepEqual(
    (sawBody as { commitments: unknown }).commitments,
    COMMITMENTS
  );
  // The SDK injected a stable request_id (idempotency key) since none was given.
  assert.ok(
    typeof (sawBody as { request_id?: string }).request_id === "string",
    "SDK must generate a stable request_id"
  );
  // Auth went out as a fresh self-verifying proof — the only issuer credential the
  // node reads — and nothing else: no bearer header for the node to ignore. The
  // body declares NO scope of its own: the issuer's scope is derived from the
  // proof, so a caller cannot widen it by putting something else in the body.
  assert.equal(sawHeaders["x-certcrypt-issuer-auth"], "proof-1");
  assert.ok(!("authorization" in sawHeaders), "no Authorization header is sent");
  const bodyKeys = Object.keys(sawBody as Record<string, unknown>);
  assert.deepEqual(
    bodyKeys.filter((k) => k !== "request_id" && k !== "commitments"),
    [],
    "the issue body carries only request_id + commitments"
  );
});

test("getOperation returns the record; 404 throws CertcryptNodeError", async () => {
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: fakeFetch((url) => {
      if (url.endsWith("/v1/operations/op_known")) {
        return {
          status: 200,
          body: {
            operation_id: "op_known",
            request_id: "R",
            state: { state: "independent_ready", upstream_operation_id: "OP-UP" },
          },
        };
      }
      return { status: 404, body: "operation not found" };
    }),
  });

  const rec = await client.getOperation("op_known");
  assert.equal(rec.state.state, "independent_ready");

  await assert.rejects(
    () => client.getOperation("op_missing"),
    (e: unknown) => e instanceof CertcryptNodeError && e.status === 404
  );
});

test("a server body that says rejected is rejected, not processing", async () => {
  // An operation can be rejected after it was accepted (e.g. a window whose
  // settlement could not be proven). Folding that into `processing` would leave
  // the issuer polling indefinitely.
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: fakeFetch((url) => {
      if (url.endsWith("/v1/operations/op_rejected")) {
        return { status: 200, body: { operation_id: "OP-UP", status: "rejected" } };
      }
      if (url.endsWith("/v1/operations/op_short")) {
        return { status: 200, body: { operation_id: "OP-UP", status: "insufficient_capacity" } };
      }
      return { status: 200, body: { operation_id: "OP-UP", status: "something_new" } };
    }),
  });

  const rejected = await client.getOperation("op_rejected");
  assert.equal(rejected.state.state, "rejected");
  const waited = await client.waitForOperation("op_rejected", { intervalMs: 1, maxAttempts: 2 });
  assert.equal(waited.state.state, "rejected");

  assert.equal((await client.getOperation("op_short")).state.state, "insufficient_capacity");
  // An unknown status is not invented into a terminal one.
  assert.equal((await client.getOperation("op_other")).state.state, "processing");
});

test("a server body that says expired is expired, terminal and carries its reason", async () => {
  // submission-set/1 §11.1: an accepted operation whose authorization ran out
  // before it could settle ends `expired`. It must stop the poller (folding it
  // into `processing` polls forever) and must not read as `rejected`.
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: fakeFetch(() => ({
      status: 200,
      body: {
        operation_id: "OP-UP",
        status: "expired",
        reason_code: "authorization_expired_before_finality",
        message: "nothing was consumed — re-submit under a fresh authorization",
      },
    })),
  });

  const op = await client.getOperation("op_expired");
  assert.deepEqual(op.state, {
    state: "expired",
    reason_code: "authorization_expired_before_finality",
    message: "nothing was consumed — re-submit under a fresh authorization",
  });
  const waited = await client.waitForOperation("op_expired", { intervalMs: 1, maxAttempts: 2 });
  assert.equal(waited.state.state, "expired");
});

test("waitForOperation polls until terminal", async () => {
  let calls = 0;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: fakeFetch(() => {
      calls++;
      // First two polls processing, then independent_ready.
      const state =
        calls < 3
          ? { state: "processing", upstream_operation_id: "OP-UP" }
          : { state: "independent_ready", upstream_operation_id: "OP-UP" };
      return {
        status: 200,
        body: { operation_id: "op_W", request_id: "R", state },
      };
    }),
  });

  const rec = await client.waitForOperation("op_W", { intervalMs: 1, maxAttempts: 10 });
  assert.equal(rec.state.state, "independent_ready");
  assert.equal(calls, 3, "should have polled 3 times");
});

test("issue retries submission_failed (idempotent: same request_id) then throws after maxAttempts", async () => {
  let calls = 0;
  const seenIds = new Set<string>();
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { maxAttempts: 3, baseMs: 1, capMs: 2 },
    fetch: fakeFetch((_url, init) => {
      calls++;
      const body = JSON.parse(init!.body as string) as { request_id: string };
      seenIds.add(body.request_id);
      return {
        status: 502,
        body: {
          request_id: body.request_id,
          results: [],
          state: { state: "submission_failed", error: "upstream unreachable" },
        },
      };
    }),
  });
  // submission_failed is RETRYABLE → retried up to maxAttempts, then throws.
  await assert.rejects(() => client.issueCommitments(COMMITMENTS));
  assert.equal(calls, 3, "should have retried up to maxAttempts");
  assert.equal(seenIds.size, 1, "every retry reused the SAME request_id (idempotent)");
});

test("issue succeeds on a later attempt after a transient failure (retry recovers)", async () => {
  let calls = 0;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { maxAttempts: 5, baseMs: 1, capMs: 2 },
    fetch: fakeFetch((_url, init) => {
      calls++;
      const body = JSON.parse(init!.body as string) as { request_id: string };
      if (calls < 3) {
        return {
          status: 502,
          body: { request_id: body.request_id, results: [], state: { state: "submission_failed", error: "down" } },
        };
      }
      return {
        status: 200,
        body: {
          request_id: body.request_id,
          submission_set_id: "set-ok",
          results: [
            { operation_id: "op_OK", commitment_index: 0, state: { state: "accepted", upstream_operation_id: "U" } },
          ],
        },
      };
    }),
  });
  const res = await client.issueCommitments(COMMITMENTS);
  assert.equal(res.results[0].state.state, "accepted");
  assert.equal(calls, 3, "recovered on the 3rd attempt");
});

test("issue: a 422 upstream refusal is not retried and surfaces the service's status", async () => {
  // The node answers 422 + IssueResponse when the upstream service refused the
  // request itself. Nothing was queued and the same bytes get the same answer, so
  // the SDK stops at once and tells the caller why.
  let calls = 0;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { maxAttempts: 5, baseMs: 1, capMs: 2 },
    fetch: fakeFetch((_url, init) => {
      calls++;
      const body = JSON.parse(init!.body as string) as { request_id: string };
      return {
        status: 422,
        body: {
          request_id: body.request_id,
          results: [],
          state: {
            state: "submission_failed",
            error: "request refused",
            upstream_status: 400,
          },
        },
      };
    }),
  });
  await assert.rejects(
    () => client.issueCommitments(COMMITMENTS),
    (e: unknown) => {
      assert.ok(e instanceof CertcryptNodeError);
      assert.equal(e.status, 422);
      assert.equal(e.code, "submission_failed");
      assert.equal(e.upstreamStatus, 400);
      assert.match(e.message, /submission_failed \(upstream HTTP 400\): request refused/);
      return true;
    }
  );
  assert.equal(calls, 1, "a definitive refusal is never resent");
});

test("issue: a 422 request error surfaces the node's error code and message", async () => {
  let calls = 0;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { maxAttempts: 5, baseMs: 1, capMs: 2 },
    fetch: fakeFetch(() => {
      calls++;
      return {
        status: 422,
        body: {
          error: "empty_submission",
          message: "the request carries no commitments",
          request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
        },
      };
    }),
  });
  await assert.rejects(
    () => client.issueCommitments(COMMITMENTS),
    (e: unknown) => {
      assert.ok(e instanceof CertcryptNodeError);
      assert.equal(e.status, 422);
      assert.equal(e.code, "empty_submission");
      assert.equal(e.upstreamStatus, null);
      assert.match(e.message, /HTTP 422 — empty_submission: the request carries no commitments/);
      return true;
    }
  );
  assert.equal(calls, 1, "a request error is never resent");
});

// ---------------------------------------------------------------------------
// by-commitment: the lookup that outlives the node
//
// A node's operation id lives in THAT node's journal. A restart with an
// in-memory journal, or an issuer moving to another node, leaves it unable to
// ask about an emission the CERTCRYPT service still holds. The capacity-evidence
// digest has no such problem — the issuer recomputes it from evidence it signed.
// ---------------------------------------------------------------------------

const REF = "c6132cdf3e82f056d284627dbe47ae603d9b2eea939523ba84dd95797c8f7aee";

test("getEmissionByCommitment signs the DIGEST as the resource, not a node id", async () => {
  // The load-bearing assertion. Binding the read to an id the node hands out
  // would let a node get an issuer to sign a read it never asked for: the issuer
  // would be signing over a value whose meaning it cannot check.
  let signedResource: string | null = null;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test/",
    issuerReadProof: (resource: string) => {
      signedResource = resource;
      return "proof-for-" + resource;
    },
    fetch: fakeFetch((url, init) => {
      assert.ok(
        url.endsWith(`/v1/emissions/by-commitment/${REF}`),
        `unexpected url ${url}`
      );
      assert.equal(
        (init?.headers as Record<string, string>)["x-certcrypt-issuer-read"],
        "proof-for-" + REF
      );
      return { status: 200, body: { operation_id: "op-api", status: "processing" } };
    }),
  });

  const rec = await client.getEmissionByCommitment(REF);
  assert.equal(signedResource, REF, "the signed resource must be the digest itself");
  assert.equal(rec.status, "processing");
});

test("a read retried after a transient failure carries a NEW issuer half every attempt", async () => {
  // The issuance service spends a read challenge on first use. Reusing the
  // first attempt's half would turn a retry that got through into a 401.
  const seen: string[] = [];
  let minted = 0;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test/",
    retry: { maxAttempts: 5, baseMs: 1, capMs: 2 },
    issuerReadProof: () => `proof-${++minted}`,
    fetch: fakeFetch((_url, init) => {
      seen.push((init?.headers as Record<string, string>)["x-certcrypt-issuer-read"]!);
      return seen.length < 3
        ? { status: 503, body: "down" }
        : { status: 200, body: { operation_id: "op-api", status: "processing" } };
    }),
  });
  await client.getEmissionByCommitment(REF);
  assert.deepEqual(seen, ["proof-1", "proof-2", "proof-3"]);
});

test("getEmissionByCommitment returns both artifacts once settled", async () => {
  // Both or neither: a package missing the settlement material does not verify,
  // so the caller must be able to tell them apart from a pending emission.
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test/",
    fetch: fakeFetch(() => ({
      status: 200,
      body: {
        operation_id: "op-api",
        status: "independent_ready",
        independence_proof: "cHJvb2Y=",
        settlement_material: "bWF0ZXJpYWw=",
      },
    })),
  });

  const rec = await client.getEmissionByCommitment(REF);
  assert.equal(rec.status, "independent_ready");
  assert.equal(rec.independence_proof, "cHJvb2Y=");
  assert.equal(rec.settlement_material, "bWF0ZXJpYWw=");
});

test("getEmissionByCommitment: 404 throws CertcryptNodeError naming the digest", async () => {
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test/",
    fetch: fakeFetch(() => ({ status: 404, body: { error: "not_found" } })),
  });

  await assert.rejects(
    () => client.getEmissionByCommitment(REF),
    (e: unknown) =>
      e instanceof CertcryptNodeError && e.status === 404 && e.message.includes(REF)
  );
});

// submission-set/1 §8.1: the producer refuses to build a set over the bound.
function countingClient() {
  const sent: { commitments: unknown[] }[] = [];
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: fakeFetch((_url, init) => {
      const body = JSON.parse(init!.body as string) as { commitments: unknown[] };
      sent.push(body);
      return {
        status: 200,
        body: {
          request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
          submission_set_id: "set-bound",
          results: body.commitments.map((_, i) => ({
            operation_id: `op-${i}`,
            commitment_index: i,
            state: { state: "accepted", upstream_operation_id: `up-${i}` },
          })),
        },
      };
    }),
  });
  return { client, sent };
}

const repeated = (n: number) => Array.from({ length: n }, () => COMMITMENTS[0]!);

test("issue sends a set of exactly MAX_SUBMISSION_SET_MEMBERS commitments", async () => {
  const { client, sent } = countingClient();
  const res = await client.issue({ commitments: repeated(MAX_SUBMISSION_SET_MEMBERS) });
  assert.equal(sent.length, 1);
  assert.equal(sent[0]!.commitments.length, MAX_SUBMISSION_SET_MEMBERS);
  assert.equal(res.results.length, MAX_SUBMISSION_SET_MEMBERS);
});

test("issue and issueCommitments refuse MAX_SUBMISSION_SET_MEMBERS + 1 commitments before sending", async () => {
  const { client, sent } = countingClient();
  const over = repeated(MAX_SUBMISSION_SET_MEMBERS + 1);
  const isTooLarge = (e: unknown) =>
    e instanceof SubmissionSetTooLargeError && e.count === MAX_SUBMISSION_SET_MEMBERS + 1;
  await assert.rejects(() => client.issue({ commitments: over }), isTooLarge);
  await assert.rejects(() => client.issueCommitments(over), isTooLarge);
  assert.equal(sent.length, 0, "the over-bound set never reaches the node");
});
