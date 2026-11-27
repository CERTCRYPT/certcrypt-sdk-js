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
 * `waitForOperation`: how a wait is scheduled, what it reports, and how it ends.
 *
 * A wait for settlement can legitimately sleep for minutes, so what it says while
 * it sleeps matters as much as when it wakes: an unannounced long sleep is
 * indistinguishable from a hang. And a wait that ends without a terminal state is
 * an error, never a record that could be mistaken for an outcome.
 */

import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { CertcryptNodeClient, CertcryptNodeError, type WaitProgress } from "./client.js";

const T0 = Date.parse("2026-08-16T12:00:00Z");
const OP = "01J0000000000000000000000A";

function win(target?: string, expected?: string) {
  return {
    window_profile: "profile_a",
    window_profile_version: "2026-07-02",
    ...(target === undefined ? {} : { target_close_by: target }),
    ...(expected === undefined ? {} : { expected_settled_by: expected }),
  };
}

function processing(target = "2020-01-01T00:00:00.000Z", progress?: unknown, expected?: string) {
  return {
    operation_id: OP,
    status: "processing",
    settlement_window: win(target, expected),
    ...(progress === undefined ? {} : { settlement_progress: progress }),
  };
}

const READY = { operation_id: OP, status: "independent_ready" };

/** Plays `bodies` in order (the last repeats); a clock whose sleeps advance it. */
function node(bodies: unknown[]) {
  const state = { calls: 0, now: T0, slept: [] as number[] };
  const client = new CertcryptNodeClient({
    baseUrl: "https://node.test",
    fetch: (async () => {
      const b = bodies[Math.min(state.calls, bodies.length - 1)];
      state.calls += 1;
      const text = JSON.stringify(b);
      return { ok: true, status: 200, text: async () => text, json: async () => b } as Response;
    }) as typeof fetch,
    clock: {
      now: () => state.now,
      sleep: async (ms: number) => {
        state.slept.push(ms);
        state.now += ms;
      },
      random: () => 0,
    },
  });
  return { client, state };
}

const AUTO = { strategy: "auto" as const, backoffBaseMs: 5, backoffCapMs: 5 };

test("maxAttempts alone also selects the fixed schedule", async () => {
  const { client, state } = node([processing()]);
  await assert.rejects(client.waitForOperation(OP, { maxAttempts: 2 }), CertcryptNodeError);
  // Fixed schedule: a 1 s interval, never the window-aware sleep.
  assert.deepEqual(state.slept, [1000, 1000]);
});

test("an explicit strategy wins over the inferred one", async () => {
  const { client, state } = node([processing()]);
  await assert.rejects(
    client.waitForOperation(OP, { maxAttempts: 2, strategy: "auto", backoffBaseMs: 5, backoffCapMs: 5 }),
    CertcryptNodeError
  );
  assert.deepEqual(state.slept, [5, 5]);
});

test("maxWaitMs bounds the wait on the client's clock", async () => {
  const { client, state } = node([processing()]);
  await assert.rejects(
    client.waitForOperation(OP, { maxWaitMs: 60, ...AUTO }),
    /did not reach a terminal state/
  );
  assert.equal(state.now - T0, 60);
});

test("a wait that runs out names the last state and the window", async () => {
  const { client } = node([processing("2026-08-16T12:00:00Z")]);
  await assert.rejects(
    client.waitForOperation(OP, { intervalMs: 1000, maxAttempts: 2 }),
    (e: unknown) => {
      assert.ok(e instanceof CertcryptNodeError);
      assert.equal(
        e.message,
        `operation ${OP} did not reach a terminal state after 2s (last state: processing); ` +
          "node expected window profile_a to close by 2026-08-16T12:00:00Z — it is OVERDUE: " +
          "settlement is taking longer than the window allows"
      );
      return true;
    }
  );
});

test("a wait that ends without a terminal state throws, naming the last state", async () => {
  const { client } = node([{ operation_id: OP, state: { state: "processing" } }]);
  await assert.rejects(
    client.waitForOperation(OP, { intervalMs: 10, maxAttempts: 3 }),
    /^CertcryptNodeError: operation 01J0000000000000000000000A did not reach a terminal state after 0s \(last state: processing\)$/
  );
});

test("the parsed progress carries only its three fields", async () => {
  const { client } = node([
    processing(undefined, {
      phase: "finality_pending",
      progress_ppm: 743_000,
      observed_at: "2026-08-16T12:00:05Z",
      block_height: 99_999,
      finality_lag: 3,
    }),
  ]);
  const rec = await client.getOperation(OP);
  assert.deepEqual(rec.settlement_progress, {
    phase: "finality_pending",
    progress_ppm: 743_000,
    observed_at: "2026-08-16T12:00:05Z",
  });
});

test("progress without a string phase is no progress", async () => {
  const { client } = node([processing(undefined, { progress_ppm: 5 })]);
  const rec = await client.getOperation(OP);
  assert.equal(rec.settlement_progress, undefined);
});

test("the progress message reads the same in every SDK", async () => {
  // Pinned verbatim: the line an integrator greps its logs for.
  const { client } = node([processing("2026-08-16T12:01:00Z"), READY]);
  const seen: WaitProgress[] = [];
  await client.waitForOperation(OP, { backoffCapMs: 30_000, onProgress: (p) => seen.push(p) });
  assert.equal(
    seen[0]!.message,
    "still processing after 1s — waiting for settlement window profile_a to close " +
      "(~2026-08-16T12:01:00Z); next check in 63s"
  );
});

test("while settlement is expected later, the message names the expected instant", async () => {
  const { client, state } = node([
    processing("2026-08-16T12:00:20Z", undefined, "2026-08-16T12:00:35Z"),
    READY,
  ]);
  const seen: WaitProgress[] = [];
  await client.waitForOperation(OP, { backoffCapMs: 60_000, onProgress: (p) => seen.push(p) });
  assert.deepEqual(state.slept, [29_000], "one sleep to the early check, 60 % of the way to the expected instant");
  assert.equal(seen[0]!.overdue, false);
  assert.equal(seen[0]!.window?.expected_settled_by, "2026-08-16T12:00:35Z");
  assert.equal(
    seen[0]!.message,
    "still processing after 1s — waiting for settlement window profile_a to close " +
      "(~2026-08-16T12:00:20Z), settlement expected by ~2026-08-16T12:00:35Z; next check in 29s"
  );
});

test("a closed window still settling before the expected instant is not overdue", async () => {
  // Close passed 10 s ago; the operator expects settlement 5 s from now.
  const { client } = node([
    processing("2026-08-16T11:59:50Z", undefined, "2026-08-16T12:00:05Z"),
    READY,
  ]);
  const seen: WaitProgress[] = [];
  await client.waitForOperation(OP, { backoffCapMs: 30_000, onProgress: (p) => seen.push(p) });
  assert.equal(seen[0]!.overdue, false);
  assert.doesNotMatch(seen[0]!.message, /OVERDUE/);
});

test("past the expected instant the message says settlement is overdue", async () => {
  const { client } = node([
    processing("2026-08-16T11:59:00Z", undefined, "2026-08-16T11:59:15Z"),
    READY,
  ]);
  const seen: WaitProgress[] = [];
  await client.waitForOperation(OP, { ...AUTO, onProgress: (p) => seen.push(p) });
  assert.equal(seen[0]!.overdue, true);
  assert.equal(
    seen[0]!.message,
    "still processing after 1s — OVERDUE: settlement is past the operator's expected instant " +
      "2026-08-16T11:59:15Z (window profile_a); retrying in 1s"
  );
});

test("a wait that runs out past the expected instant names it", async () => {
  const { client } = node([processing("2026-08-16T11:59:00Z", undefined, "2026-08-16T11:59:15Z")]);
  await assert.rejects(
    client.waitForOperation(OP, { intervalMs: 1000, maxAttempts: 2 }),
    (e: unknown) => {
      assert.ok(e instanceof CertcryptNodeError);
      assert.equal(
        e.message,
        `operation ${OP} did not reach a terminal state after 2s (last state: processing); ` +
          "operator expected window profile_a to be settled by 2026-08-16T11:59:15Z — it is " +
          "OVERDUE: settlement is past the operator's expected instant"
      );
      return true;
    }
  );
});

test("a wait that runs out before the expected instant does not call it overdue", async () => {
  const { client } = node([processing("2026-08-16T12:00:20Z", undefined, "2026-08-16T12:00:35Z")]);
  await assert.rejects(
    client.waitForOperation(OP, { intervalMs: 1000, maxAttempts: 2 }),
    (e: unknown) => {
      assert.ok(e instanceof CertcryptNodeError);
      assert.equal(
        e.message,
        `operation ${OP} did not reach a terminal state after 2s (last state: processing); ` +
          "operator expected window profile_a to be settled by 2026-08-16T12:00:35Z"
      );
      return true;
    }
  );
});

test("a callback that throws never breaks the wait", async () => {
  const { client, state } = node([processing(), processing(), READY]);
  const rec = await client.waitForOperation(OP, {
    ...AUTO,
    onProgress: () => {
      throw new Error("the integrator's logger is broken");
    },
  });
  assert.equal(rec.state.state, "independent_ready");
  assert.equal(state.calls, 3);
});

test("a long sleep with no listener is logged at info", async () => {
  const info = mock.method(console, "info", () => {});
  try {
    const { client } = node([processing("2026-08-16T12:01:00Z"), READY]);
    await client.waitForOperation(OP, { backoffCapMs: 30_000 });
    assert.deepEqual(
      info.mock.calls.map((c) => c.arguments[0]),
      [
        `[certcrypt] operation ${OP}: still processing after 1s — waiting for settlement ` +
          "window profile_a to close (~2026-08-16T12:01:00Z); next check in 63s",
      ]
    );
  } finally {
    info.mock.restore();
  }
});

test("a short sleep with no listener is not logged", async () => {
  const info = mock.method(console, "info", () => {});
  try {
    const { client } = node([{ operation_id: OP, status: "processing" }, READY]);
    await client.waitForOperation(OP, { backoffBaseMs: 5, backoffCapMs: 5 });
    assert.equal(info.mock.callCount(), 0);
  } finally {
    info.mock.restore();
  }
});
