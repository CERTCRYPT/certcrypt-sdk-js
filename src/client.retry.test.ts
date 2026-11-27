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
 * How `issue` behaves while the node is restarting, refusing, or asking for a
 * pause — the transport-retry policy wired into the real client. A fake clock
 * makes the waits observable without spending them.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { CertcryptNodeClient, CertcryptNodeError } from "./client.js";
import { ZERO_DATA_PROFILE } from "./artifacts/capacity-evidence.js";

type Reply =
  | { status: number; body?: unknown; retryAfter?: string }
  | { refuse: true };

/** A fetch that plays `replies` in order, plus a clock whose sleeps advance it. */
function scripted(replies: Reply[]) {
  let now = 1_000_000;
  const slept: number[] = [];
  const seenIds = new Set<string>();
  let calls = 0;
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const r = replies[Math.min(calls, replies.length - 1)];
    calls += 1;
    if (init?.body) seenIds.add((JSON.parse(init.body as string) as { request_id: string }).request_id);
    if ("refuse" in r) throw new TypeError("fetch failed: ECONNREFUSED");
    const text = r.body === undefined ? "" : JSON.stringify(r.body);
    const headers = new Headers(r.retryAfter ? { "retry-after": r.retryAfter } : {});
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      headers,
      json: async () => JSON.parse(text),
      text: async () => text,
    } as Response;
  }) as typeof fetch;
  const clock = {
    now: () => now,
    sleep: async (ms: number) => {
      slept.push(ms);
      now += ms;
    },
  };
  return { fetchImpl, clock, slept, seenIds, calls: () => calls };
}

const COMMITMENTS = [
  { capacity_evidence: { profile: ZERO_DATA_PROFILE }, operative: { holder_id: "h", pool_id: "p" } },
];

const ACCEPTED = {
  request_id: "R",
  submission_set_id: "S",
  results: [{ operation_id: "op_1", commitment_index: 0, state: { state: "accepted", upstream_operation_id: "U" } }],
};

const RESTARTING = { status: 503, retryAfter: "10", body: { error: "node_restarting" } };

test("a node's Retry-After is waited out exactly and never spends an attempt", async () => {
  const s = scripted([RESTARTING, RESTARTING, RESTARTING, { status: 200, body: ACCEPTED }]);
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    // Two counted attempts would end a client that counted the pauses.
    retry: { maxAttempts: 2 },
    fetch: s.fetchImpl,
    clock: s.clock,
  });
  const res = await client.issueCommitments(COMMITMENTS);
  assert.equal(res.results[0].state.state, "accepted");
  assert.deepEqual(s.slept, [10_000, 10_000, 10_000], "exactly what the node asked");
  assert.equal(s.seenIds.size, 1, "one request_id across every retry");
});

test("a restart with the port closed is waited out by time, not by a count", async () => {
  // Twelve refused connections: the time budget bounds the retrying, not a count.
  const replies: Reply[] = Array.from({ length: 12 }, () => ({ refuse: true }) as Reply);
  replies.push({ status: 200, body: ACCEPTED });
  const s = scripted(replies);
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { baseMs: 10, capMs: 100 },
    fetch: s.fetchImpl,
    clock: s.clock,
  });
  const res = await client.issueCommitments(COMMITMENTS);
  assert.equal(res.results[0].state.state, "accepted");
  assert.equal(s.calls(), 13);
});

test("the time budget ends the retrying, and the error says why", async () => {
  const s = scripted([{ refuse: true }]);
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { maxElapsedMs: 5_000, baseMs: 1_000, capMs: 1_000 },
    fetch: s.fetchImpl,
    clock: s.clock,
  });
  await assert.rejects(client.issueCommitments(COMMITMENTS), /gave up after/);
  const total = s.slept.reduce((a, b) => a + b, 0);
  assert.ok(total <= 5_000, `never sleeps past the budget (slept ${total} ms)`);
});

test("a requested pause longer than the budget gives up at once, with the wait attached", async () => {
  const s = scripted([{ status: 503, retryAfter: "600", body: { error: "node_restarting" } }]);
  const client = new CertcryptNodeClient({ baseUrl: "http://node.test", fetch: s.fetchImpl, clock: s.clock });
  const err = await client.issueCommitments(COMMITMENTS).then(
    () => assert.fail("must give up"),
    (e: unknown) => e as CertcryptNodeError
  );
  assert.equal(err.status, 503);
  assert.equal(err.retryAfterMs, 600_000, "the caller can still see when to come back");
  assert.deepEqual(s.slept, [], "no partial wait that could not succeed");
});

test("a refusal about the request is not retried", async () => {
  const s = scripted([{ status: 401, body: { error: "unauthorized" } }]);
  const client = new CertcryptNodeClient({ baseUrl: "http://node.test", fetch: s.fetchImpl, clock: s.clock });
  await assert.rejects(client.issueCommitments(COMMITMENTS), (e: unknown) => {
    assert.ok(e instanceof CertcryptNodeError);
    assert.equal(e.status, 401);
    return true;
  });
  assert.equal(s.calls(), 1);
});

test("accepted_for_retry per member is final: the node holds the set, the ids are good", async () => {
  const s = scripted([
    {
      status: 202,
      body: {
        request_id: "R",
        submission_set_id: "S",
        results: [
          { operation_id: "op_a", commitment_index: 0, state: { state: "accepted_for_retry", error: "retry_later" } },
        ],
      },
    },
  ]);
  const client = new CertcryptNodeClient({ baseUrl: "http://node.test", fetch: s.fetchImpl, clock: s.clock });
  const res = await client.issueCommitments(COMMITMENTS);
  assert.equal(res.results[0].operation_id, "op_a");
  assert.equal(s.calls(), 1, "not resubmitted");
});

test("a read that reveals a late member's upstream id hands it over", async () => {
  const learned: Array<[string, string]> = [];
  const s = scripted([
    { status: 200, body: { operation_id: "op_a", state: { state: "accepted", upstream_operation_id: "UP-9" } } },
  ]);
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: s.fetchImpl,
    clock: s.clock,
    onUpstreamOperationId: (op, up) => learned.push([op, up]),
  });
  await client.getOperation("op_a");
  assert.deepEqual(learned, [["op_a", "UP-9"]]);
});

test("dead letters are listed and redriven through the node", async () => {
  const urls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    urls.push(`${init?.method ?? "GET"} ${url}`);
    const body = url.endsWith("/v1/outbox/dead")
      ? { dead: [{ request_id: "R1", attempts: 12, created_at_ms: 5, last_error: "HTTP 401" }] }
      : { request_id: "R1", state: "pending" };
    const text = JSON.stringify(body);
    return {
      ok: true,
      status: url.endsWith("/redrive") ? 202 : 200,
      headers: new Headers(),
      json: async () => body,
      text: async () => text,
    } as Response;
  }) as typeof fetch;
  const client = new CertcryptNodeClient({ baseUrl: "http://node.test", fetch: fetchImpl });
  const dead = await client.listDeadLetters();
  assert.deepEqual(dead, [{ requestId: "R1", attempts: 12, createdAtMs: 5, lastError: "HTTP 401" }]);
  await client.redriveDeadLetter("R1");
  assert.deepEqual(urls, [
    "GET http://node.test/v1/outbox/dead",
    "POST http://node.test/v1/outbox/dead/R1/redrive",
  ]);
});

test("a rejection before member evaluation is final, though the node sends it as 200", async () => {
  const s = scripted([
    {
      status: 200,
      body: { request_id: "R", results: [], state: { state: "pre_evaluation_rejected", reason_code: "x", message: "m" } },
    },
  ]);
  const client = new CertcryptNodeClient({ baseUrl: "http://node.test", fetch: s.fetchImpl, clock: s.clock });
  const res = await client.issueCommitments(COMMITMENTS);
  assert.equal(res.state?.state, "pre_evaluation_rejected");
  assert.equal(s.calls(), 1, "the same set always gets the same answer");
});
