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
 * `client.ts` — settlement-window scheduling: the node reports WHEN it expects to
 * settle, and the SDK schedules its next check around that instead of spinning.
 *
 * Split out of `client.test.ts` by topic, not by module: these cover one coherent
 * concern (window-aware waiting and the disclosure boundary around it), and mixing
 * them into the transport tests would bury both.
 *
 * The privacy tests here are the important ones: the window is operational
 * information, and the operation's COST must never ride along with it.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CertcryptNodeClient,
  isSettlementOverdue,
  nextPollDelayMs,
  type WaitProgress,
} from "./client.js";

const T0 = Date.parse("2026-08-16T12:00:00.000Z");
/** No random spread: pins the scheduled instants exactly. */
const NO_SPREAD = () => 0;
/**
 * A window fixture. The profile name here is an OPAQUE placeholder: these tests
 * assert that whatever the node reports is carried through and logged, never that
 * any particular name is valid. Profile names belong to the rules domain and are
 * deliberately not pinned by this suite.
 */
const win = (target?: string, expected?: string) => ({
  window_profile: "profile_a",
  window_profile_version: "2026-07-02",
  ...(target ? { target_close_by: target } : {}),
  ...(expected ? { expected_settled_by: expected } : {}),
});

test("waits until the window close instead of polling on a fixed interval", () => {
  // Target 20s out: ONE sleep to the window (+ the settling margin), not 20 polls.
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 1,
    now: T0,
    window: win("2026-08-16T12:00:20.000Z"),
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, false);
  assert.equal(delayMs, 23_000, "sleeps to the close target plus the settling margin");
});

test("a passed target reports overdue and falls back to backoff", () => {
  // The window's close target has passed and the operation is still not terminal.
  // The poller must keep going AND say it is late.
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 3,
    now: T0,
    window: win("2026-08-16T11:59:00.000Z"), // a minute ago
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, true, "a passed close target means the operation is late");
  assert.equal(delayMs, 4000, "backoff, not a busy spin");
});

// ---------------------------------------------------------------------------
// expected_settled_by: the operator's own estimate of when the settlement is
// anchored and final. When present, it replaces the close-plus-margin guess.
// ---------------------------------------------------------------------------

const CLOSE = "2026-08-16T12:00:20.000Z"; // T0 + 20 s
const SETTLED = "2026-08-16T12:00:35.000Z"; // T0 + 35 s

test("with an expected settlement instant, the first check is 60 % of the way from the close", () => {
  // Close at +20 s, expected at +35 s: the span is 15 s, so the early check is at
  // +20 + 9 = +29 s. Most settlements land well before the operator's headroom.
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 1,
    now: T0,
    window: win(CLOSE, SETTLED),
    backoffBaseMs: 1000,
    backoffCapMs: 60_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, false);
  assert.equal(delayMs, 29_000, "sleeps to the early check, not to the expected instant");
});

test("after the early check, the next one is the expected instant plus 1 s", () => {
  const now = Date.parse("2026-08-16T12:00:29.200Z"); // just after the early check
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 2,
    now,
    window: win(CLOSE, SETTLED),
    backoffBaseMs: 1000,
    backoffCapMs: 60_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, false);
  assert.equal(delayMs, 6_800, "two checks in total before overdue: early, then expected + 1 s");
});

test("each scheduled check is pushed back by at most 1 s, never earlier", () => {
  const at = (r: number) =>
    nextPollDelayMs({
      attempt: 1,
      now: T0,
      window: win(CLOSE, SETTLED),
      backoffBaseMs: 1000,
      backoffCapMs: 60_000,
      random: () => r,
    }).delayMs;
  assert.equal(at(0), 29_000);
  assert.equal(at(0.5), 29_500);
  assert.ok(at(0.9999) <= 30_000 && at(0.9999) >= 29_000, "spread stays within 0..1 s");
});

test("between the close and the expected settlement instant the operation is not overdue", () => {
  const now = Date.parse("2026-08-16T12:00:30.000Z"); // 10 s after close, 5 s before expected
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 2,
    now,
    window: win(CLOSE, SETTLED),
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, false, "a closed window that is still settling is on time");
  assert.equal(delayMs, 6000, "sleeps the rest of the way to the expected instant");
  assert.equal(isSettlementOverdue(win(CLOSE, SETTLED), now), false);
});

test("past the expected settlement instant the operation is overdue", () => {
  const now = Date.parse("2026-08-16T12:00:40.000Z"); // 5 s after expected
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 3,
    now,
    window: win(CLOSE, SETTLED),
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, true);
  assert.equal(delayMs, 4000, "backoff, not a busy spin");
  assert.equal(isSettlementOverdue(win(CLOSE, SETTLED), now), true);
});

test("without an expected settlement instant, a passed close is overdue", () => {
  const now = Date.parse("2026-08-16T12:00:30.000Z");
  assert.equal(isSettlementOverdue(win(CLOSE), now), true);
  assert.equal(isSettlementOverdue(win(), now), false, "no instant, no verdict");
  assert.equal(isSettlementOverdue(undefined, now), false);
});

test("an unparseable expected settlement instant falls back to the close", () => {
  const { delayMs, overdue } = nextPollDelayMs({
    attempt: 1,
    now: T0,
    window: win(CLOSE, "not-a-time"),
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(overdue, false);
  assert.equal(delayMs, 23_000, "close target plus the settling margin");
});

test("a far-future expected settlement instant is clamped to the scheduled-sleep cap (10 min)", () => {
  const { delayMs } = nextPollDelayMs({
    attempt: 1,
    now: T0,
    window: win(CLOSE, "2026-08-16T18:00:00.000Z"),
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(delayMs, 600_000, "one sleep towards a check never exceeds 10 min");
});

test("no estimate -> exponential backoff with a cap, never a 1s spin", () => {
  const d = (attempt: number) =>
    nextPollDelayMs({ attempt, now: T0, backoffBaseMs: 1000, backoffCapMs: 10_000 }).delayMs;
  assert.deepEqual([d(1), d(2), d(3), d(4)], [1000, 2000, 4000, 8000]);
  assert.equal(d(9), 10_000, "capped");
});

test("a far-future target cannot park the poller for hours: one sleep is at most 10 min", () => {
  const { delayMs } = nextPollDelayMs({
    attempt: 1,
    now: T0,
    window: win("2026-08-16T18:00:00.000Z"), // 6h out
    backoffBaseMs: 1000,
    backoffCapMs: 30_000,
    random: NO_SPREAD,
  });
  assert.equal(delayMs, 600_000, "clamped to the scheduled-sleep cap, not 6 h");
});

/** A node record for an operation still being settled, with the window attached. */
function processingBody(target: string) {
  return {
    operation_id: "01J0000000000000000000000A",
    status: "processing",
    settlement_window: win(target),
  };
}

function clientWith(routes: (url: string) => { status: number; body: unknown }) {
  return new CertcryptNodeClient({
    baseUrl: "https://node.test",
    fetch: (async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      const { status, body } = routes(url);
      return {
        ok: status >= 200 && status < 300,
        status,
        text: async () => JSON.stringify(body),
        json: async () => body,
      } as unknown as Response;
    }) as typeof fetch,
  });
}

test("the wait reports progress so a long sleep is not mistaken for a hang", async () => {
  let calls = 0;
  const client = clientWith(() => {
    calls += 1;
    // Terminal on the 2nd poll so the wait ends quickly.
    if (calls >= 2) {
      return {
        status: 200,
        body: { operation_id: "x", status: "independent_ready" },
      };
    }
    // A target already in the past → overdue → short backoff, so the test is fast.
    return { status: 200, body: processingBody("2020-01-01T00:00:00.000Z") };
  });

  const seen: WaitProgress[] = [];
  const rec = await client.waitForOperation("01J0000000000000000000000A", {
    strategy: "auto",
    backoffBaseMs: 5,
    backoffCapMs: 5,
    onProgress: (p) => seen.push(p),
  });

  assert.equal(rec.state.state, "independent_ready");
  assert.ok(seen.length >= 1, "progress must be reported while waiting");
  const p = seen[0]!;
  assert.equal(p.overdue, true, "a passed target is reported as overdue");
  assert.equal(p.window?.window_profile, "profile_a");
  // The message is what an integrator logs; it must NAME the situation.
  assert.match(p.message, /OVERDUE/);
  assert.match(p.message, /profile_a/);
});

test("explicit intervalMs/maxAttempts select fixed-interval polling", async () => {
  let calls = 0;
  const client = clientWith(() => {
    calls += 1;
    return { status: 200, body: processingBody("2020-01-01T00:00:00.000Z") };
  });
  // 3 attempts at a 1ms interval: must give up after exactly 3 polls,
  // and must NOT switch itself to the window-aware strategy.
  await assert.rejects(
    client.waitForOperation("01J0000000000000000000000A", { intervalMs: 1, maxAttempts: 3 }),
    /did not reach a terminal state/
  );
  assert.equal(calls, 3, "an explicit attempt budget is honored");
});

test("maxWaitMs bounds the wait by wall clock, not by attempt count", async () => {
  const client = clientWith(() => ({
    status: 200,
    body: processingBody("2020-01-01T00:00:00.000Z"),
  }));
  const t0 = Date.now();
  await assert.rejects(
    client.waitForOperation("01J0000000000000000000000A", {
      strategy: "auto",
      backoffBaseMs: 5,
      backoffCapMs: 5,
      maxWaitMs: 60,
    }),
    /did not reach a terminal state/
  );
  assert.ok(Date.now() - t0 < 2000, "must stop at the wall-clock bound");
});

// ---------------------------------------------------------------------------
// ZERO-DATA: the window is operational; the cost must never ride along with it.
// ---------------------------------------------------------------------------

test("the parsed window carries ONLY scheduling fields — never a cost", async () => {
  // A misconfigured server adds unknown fields to the window. The SDK copies the
  // three scheduling fields explicitly (never spreads), so nothing else can reach
  // a consumer or its logs.
  const client = clientWith(() => ({
    status: 200,
    body: {
      operation_id: "x",
      status: "processing",
      settlement_window: {
        window_profile: "profile_a",
        window_profile_version: "2026-07-02",
        target_close_by: "2026-08-16T12:00:40.000Z",
        expected_settled_by: "2026-08-16T12:00:55.000Z",
        // None of these may survive:
        extra_field_a: "value-a",
        extra_field_b: "value-b",
        vendor_note: "unexpected",
      },
    },
  }));

  const rec = await client.getOperation("01J0000000000000000000000A");
  const w = rec.settlement_window!;
  assert.deepEqual(Object.keys(w).sort(), [
    "expected_settled_by",
    "target_close_by",
    "window_profile",
    "window_profile_version",
  ]);
  const serialized = JSON.stringify(rec);
  for (const leak of ["extra_field_a", "extra_field_b", "vendor_note", "value-a", "value-b", "unexpected"]) {
    assert.ok(!serialized.includes(leak), `unknown field leaked into the record: ${leak}`);
  }
});

test("a window without an expected settlement instant parses without one", async () => {
  const client = clientWith(() => ({
    status: 200,
    body: { operation_id: "x", status: "processing", settlement_window: win(CLOSE) },
  }));
  const rec = await client.getOperation("01J0000000000000000000000A");
  assert.equal(rec.settlement_window?.target_close_by, CLOSE);
  assert.equal(rec.settlement_window?.expected_settled_by, undefined);
});

test("a node that does not report a window still works (older nodes)", async () => {
  const client = clientWith(() => ({
    status: 200,
    body: { operation_id: "x", status: "processing" },
  }));
  const rec = await client.getOperation("01J0000000000000000000000A");
  assert.equal(rec.settlement_window, undefined);
  // And scheduling degrades to backoff rather than throwing.
  assert.equal(
    nextPollDelayMs({ attempt: 1, now: T0, backoffBaseMs: 1000, backoffCapMs: 30_000 }).delayMs,
    1000
  );
});

// ---------------------------------------------------------------------------
// Settlement progress: "queued behind a window" vs "on chain, waiting for the
// substrate". Without the distinction, both look like an opaque `processing` for
// the window plus the substrate's finality lag.
// ---------------------------------------------------------------------------

/** Still settling: settled on the substrate, awaiting irreversibility. */
function finalityPendingBody(ppm?: number) {
  return {
    operation_id: "01J0000000000000000000000A",
    status: "processing",
    settlement_window: win("2020-01-01T00:00:00.000Z"),
    settlement_progress: {
      phase: "finality_pending",
      ...(ppm === undefined ? {} : { progress_ppm: ppm }),
    },
  };
}

test("a settlement waiting on the chain says so, instead of blaming the window", async () => {
  let calls = 0;
  const client = clientWith(() => {
    calls += 1;
    if (calls >= 2) {
      return { status: 200, body: { operation_id: "x", status: "independent_ready" } };
    }
    return { status: 200, body: finalityPendingBody(743_000) };
  });

  const seen: WaitProgress[] = [];
  await client.waitForOperation("01J0000000000000000000000A", {
    strategy: "auto",
    backoffBaseMs: 5,
    backoffCapMs: 5,
    onProgress: (p) => seen.push(p),
  });

  const p = seen[0]!;
  assert.equal(p.settlement?.phase, "finality_pending");
  assert.equal(p.settlement?.progress_ppm, 743_000);
  // The message must name the real reason for the wait. Once settlement is on the
  // substrate, the window is no longer what is holding things up, and saying "OVERDUE window"
  // there would point the integrator at the wrong thing entirely.
  assert.match(p.message, /irreversibility/);
  assert.match(p.message, /74%/, "ppm is rendered as a human percentage");
  assert.doesNotMatch(p.message, /OVERDUE/);
});

test("a missing progress bar still reports the phase, without inventing a percentage", async () => {
  let calls = 0;
  const client = clientWith(() => {
    calls += 1;
    if (calls >= 2) {
      return { status: 200, body: { operation_id: "x", status: "independent_ready" } };
    }
    // No progress_ppm: pre-broadcast sampling, or an immediate-finality substrate.
    return { status: 200, body: finalityPendingBody(undefined) };
  });

  const seen: WaitProgress[] = [];
  await client.waitForOperation("01J0000000000000000000000A", {
    strategy: "auto",
    backoffBaseMs: 5,
    backoffCapMs: 5,
    onProgress: (p) => seen.push(p),
  });

  const p = seen[0]!;
  assert.equal(p.settlement?.progress_ppm, undefined);
  assert.match(p.message, /irreversibility/);
  assert.doesNotMatch(p.message, /%/, "no percentage is invented when none was reported");
});

test("an operation still queued keeps the window-oriented message", async () => {
  // The finality branch must not swallow the window messaging for operations
  // that have not been broadcast yet.
  let calls = 0;
  const client = clientWith(() => {
    calls += 1;
    if (calls >= 2) {
      return { status: 200, body: { operation_id: "x", status: "independent_ready" } };
    }
    return {
      status: 200,
      body: {
        operation_id: "01J0000000000000000000000A",
        status: "processing",
        settlement_window: win("2020-01-01T00:00:00.000Z"),
        settlement_progress: { phase: "queued" },
      },
    };
  });

  const seen: WaitProgress[] = [];
  await client.waitForOperation("01J0000000000000000000000A", {
    strategy: "auto",
    backoffBaseMs: 5,
    backoffCapMs: 5,
    onProgress: (p) => seen.push(p),
  });

  const p = seen[0]!;
  assert.equal(p.settlement?.phase, "queued");
  assert.match(p.message, /OVERDUE/, "a queued operation is still judged by its window");
  assert.doesNotMatch(p.message, /irreversibility/);
});

test("the progress reported is sticky: a tick that omits it does not regress", async () => {
  // The node may answer without the indicator (a node that does not send it, a partial read). The
  // poller must keep reporting the last thing it actually knew rather than
  // pretending the settlement went backward.
  let calls = 0;
  const client = clientWith(() => {
    calls += 1;
    if (calls === 1) return { status: 200, body: finalityPendingBody(500_000) };
    if (calls === 2) {
      return {
        status: 200,
        body: {
          operation_id: "01J0000000000000000000000A",
          status: "processing",
          settlement_window: win("2020-01-01T00:00:00.000Z"),
        },
      };
    }
    return { status: 200, body: { operation_id: "x", status: "independent_ready" } };
  });

  const seen: WaitProgress[] = [];
  await client.waitForOperation("01J0000000000000000000000A", {
    strategy: "auto",
    backoffBaseMs: 5,
    backoffCapMs: 5,
    onProgress: (p) => seen.push(p),
  });

  assert.ok(seen.length >= 2, "needs at least two ticks to observe the omission");
  assert.equal(seen[1]!.settlement?.phase, "finality_pending");
  assert.equal(seen[1]!.settlement?.progress_ppm, 500_000);
});
