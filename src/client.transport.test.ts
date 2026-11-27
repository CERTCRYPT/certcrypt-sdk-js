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
 * The transport around every request: the 30 s bound, the retried reads, the
 * liveness probe that never throws, and the submit whose answer was lost.
 *
 * Each of these is a decision about a misbehaving node — one that accepts the
 * connection and never answers, restarts mid-read, or answers 200 with a body
 * that is not one — and none of them shows against a healthy node.
 */

import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { CertcryptNodeClient, CertcryptNodeError, REQUEST_TIMEOUT_MS } from "./client.js";
import { ZERO_DATA_PROFILE } from "./artifacts/capacity-evidence.js";

type Reply = { status: number; body?: unknown; raw?: string } | { refuse: true };

/** A fetch that plays `replies` in order (the last repeats), recording each
 *  request, plus a clock whose sleeps advance it. */
function scripted(replies: Reply[]) {
  const seen: Array<{ url: string; method: string; body: unknown; signal: unknown }> = [];
  let now = 1_000_000;
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    seen.push({
      url,
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(init.body as string) : null,
      signal: init?.signal,
    });
    const r = replies[Math.min(seen.length - 1, replies.length - 1)]!;
    if ("refuse" in r) throw new TypeError("fetch failed: ECONNREFUSED");
    const text = r.raw ?? (r.body === undefined ? "" : JSON.stringify(r.body));
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      headers: new Headers(),
      json: async () => JSON.parse(text),
      text: async () => text,
    } as Response;
  }) as typeof fetch;
  const client = new CertcryptNodeClient({
    baseUrl: "https://node.test",
    fetch: fetchImpl,
    clock: { now: () => now, sleep: async (ms: number) => void (now += ms) },
  });
  return { client, seen };
}

const COMMITMENTS = [
  { capacity_evidence: { profile: ZERO_DATA_PROFILE }, operative: { holder_id: "h", pool_id: "p" } },
];
const ACCEPTED = {
  request_id: "R",
  submission_set_id: "S",
  results: [{ operation_id: "op-1", commitment_index: 0, state: { state: "accepted" } }],
};
const OP_BODY = { operation_id: "op-1", state: { state: "processing" } };
const REF = "ab".repeat(32);
const ACTIVATE = {
  code: "c",
  holderKeySetRoot: "r",
  keySetDisclosure: {},
  keySetPossessionB64: "cA==",
  rulesVersion: "rules/conformance",
  systemRootFingerprint: "aa".repeat(32),
  validUntil: "2100-01-01T00:00:00Z",
};

// --- health -----------------------------------------------------------------

test("health is true on a 2xx", async () => {
  const { client } = scripted([{ status: 200, raw: "ok" }]);
  assert.equal(await client.health(), true);
});

test("health is false on an error status", async () => {
  const { client } = scripted([{ status: 503, raw: "down" }]);
  assert.equal(await client.health(), false);
});

test("health is false, not a throw, on a transport failure", async () => {
  const { client, seen } = scripted([{ refuse: true }]);
  assert.equal(await client.health(), false);
  assert.equal(seen.length, 1, "a liveness probe is one request, never retried");
});

test("health gives up after 30 s and reports false", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const client = new CertcryptNodeClient({
      baseUrl: "https://node.test",
      // A node that accepts the connection and never answers.
      fetch: ((_u: RequestInfo | URL, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        })) as typeof fetch,
    });
    const pending = client.health();
    mock.timers.tick(REQUEST_TIMEOUT_MS);
    assert.equal(await pending, false);
  } finally {
    mock.timers.reset();
  }
});

// --- the 30 s bound on every request -----------------------------------------

test("the request timeout is 30 seconds", () => {
  assert.equal(REQUEST_TIMEOUT_MS, 30_000);
});

test("every request carries the timeout", async () => {
  const { client, seen } = scripted([
    { status: 200, raw: "ok" }, // health
    { status: 200, body: ACCEPTED }, // issue
    {
      status: 409,
      body: { error: "integration_key_replaced", message: "use the latest key" },
    }, // activate
    { status: 200, body: OP_BODY }, // getOperation
    { status: 200, body: { operation_id: "op-1", status: "processing" } }, // by-commitment
    { status: 200, body: { emissions: [], truncated: false } }, // unresolved
    { status: 200, body: { dead: [] } }, // dead letters
    { status: 202, body: {} }, // redrive
  ]);
  await client.health();
  await client.issue({ commitments: COMMITMENTS as never });
  await assert.rejects(client.activate(ACTIVATE));
  await client.getOperation("op-1");
  await client.getEmissionByCommitment(REF);
  await client.listUnresolvedEmissions("2026-01-01T00:00:00Z");
  await client.listDeadLetters();
  await client.redriveDeadLetter("R1");
  assert.equal(seen.length, 8);
  for (const s of seen) {
    assert.ok(s.signal instanceof AbortSignal, `${s.method} ${s.url} carries no timeout`);
  }
});

// --- reads are retried under the transport-retry policy -----------------------

test("getOperation rides out a 503", async () => {
  const { client, seen } = scripted([{ status: 503, raw: "restarting" }, { status: 200, body: OP_BODY }]);
  const rec = await client.getOperation("op-1");
  assert.equal(rec.state.state, "processing");
  assert.equal(seen.length, 2);
});

test("getOperation rides out a refused connection", async () => {
  const { client, seen } = scripted([{ refuse: true }, { status: 200, body: OP_BODY }]);
  const rec = await client.getOperation("op-1");
  assert.equal(rec.state.state, "processing");
  assert.equal(seen.length, 2);
});

test("getOperation does not retry a 404", async () => {
  const { client, seen } = scripted([{ status: 404, raw: "no such operation" }]);
  await assert.rejects(client.getOperation("op-x"), (e: unknown) => {
    assert.ok(e instanceof CertcryptNodeError);
    assert.equal(e.status, 404);
    return true;
  });
  assert.equal(seen.length, 1);
});

test("getEmissionByCommitment rides out a 503", async () => {
  const { client, seen } = scripted([
    { status: 503, raw: "restarting" },
    { status: 200, body: { operation_id: "op-1", status: "processing" } },
  ]);
  const rec = await client.getEmissionByCommitment(REF);
  assert.equal(rec.status, "processing");
  assert.equal(seen.length, 2);
});

test("listUnresolvedEmissions rides out a 503", async () => {
  const { client, seen } = scripted([
    { status: 503, raw: "restarting" },
    { status: 200, body: { emissions: [], truncated: false } },
  ]);
  const page = await client.listUnresolvedEmissions("2026-01-01T00:00:00Z");
  assert.deepEqual(page, { emissions: [], truncated: false });
  assert.equal(seen.length, 2);
});

test("listUnresolvedEmissions carries each emission's window instants", async () => {
  const { client } = scripted([
    {
      status: 200,
      body: {
        emissions: [
          {
            operation_id: "op-1",
            status: "processing",
            updated_at: "2026-08-16T12:00:00Z",
            target_close_by: "2026-08-16T12:00:20Z",
            expected_settled_by: "2026-08-16T12:00:35Z",
            commitment_count: 1,
          },
          { operation_id: "op-2", status: "processing", updated_at: "2026-08-16T12:00:00Z" },
        ],
        truncated: false,
      },
    },
  ]);
  const page = await client.listUnresolvedEmissions("2026-01-01T00:00:00Z");
  assert.equal(page.emissions[0]!.targetCloseBy, "2026-08-16T12:00:20Z");
  assert.equal(page.emissions[0]!.expectedSettledBy, "2026-08-16T12:00:35Z");
  assert.equal(page.emissions[1]!.targetCloseBy, null);
  assert.equal(page.emissions[1]!.expectedSettledBy, null);
});

test("listDeadLetters rides out a 503", async () => {
  const { client, seen } = scripted([
    { status: 503, raw: "restarting" },
    { status: 200, body: { dead: [] } },
  ]);
  assert.deepEqual(await client.listDeadLetters(), []);
  assert.equal(seen.length, 2);
});

test("a read that keeps failing gives up on the time budget, saying so", async () => {
  const { client } = scripted([{ status: 503, raw: "down" }]);
  await assert.rejects(client.getOperation("op-1"), /gave up after \d+s and \d+ attempt\(s\)/);
});

// --- a 2xx submit whose body is not JSON --------------------------------------

test("a 2xx submit whose body is not JSON is retried with the same request_id", async () => {
  const { client, seen } = scripted([
    { status: 200, raw: "<html>proxy error</html>" },
    { status: 200, body: ACCEPTED },
  ]);
  const res = await client.issue({ commitments: COMMITMENTS as never });
  assert.equal(res.results?.[0]?.operation_id, "op-1");
  assert.equal(seen.length, 2);
  const ids = seen.map((s) => (s.body as { request_id: string }).request_id);
  assert.equal(ids[0], ids[1], "the retry is the SAME request");
});

test("a 2xx submit whose body is JSON but not an object is retried too", async () => {
  const { client, seen } = scripted([{ status: 200, body: [1, 2] }, { status: 200, body: ACCEPTED }]);
  await client.issue({ commitments: COMMITMENTS as never });
  assert.equal(seen.length, 2);
});

test("a submit that never gets a readable answer gives up naming it", async () => {
  const { client } = scripted([{ status: 200, raw: "not json" }]);
  await assert.rejects(
    client.issue({ commitments: COMMITMENTS as never }),
    /^CertcryptNodeError: issue failed: unparseable node response — gave up after/
  );
});

// --- activation refusals say why -----------------------------------------------

test("an activation refusal carries the node's code and message", async () => {
  const { client } = scripted([
    { status: 409, body: { error: "integration_key_replaced", message: "use the latest key" } },
  ]);
  await assert.rejects(client.activate(ACTIVATE), (e: unknown) => {
    assert.ok(e instanceof CertcryptNodeError);
    assert.equal(e.message, "activate failed: HTTP 409 — integration_key_replaced: use the latest key");
    assert.equal(e.status, 409);
    assert.equal(e.code, "integration_key_replaced");
    return true;
  });
});
