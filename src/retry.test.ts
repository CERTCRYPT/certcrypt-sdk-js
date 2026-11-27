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
 * The transport-retry policy's reading of `Retry-After`, with inline data.
 *
 * The full decision table is documented in `retry.ts`; these are
 * the parser edges.
 */

import assert from "node:assert/strict";
import test from "node:test";

import { decideRetry, parseRetryAfter, RETRY_AFTER_MAX_MS } from "./retry.js";

test("Retry-After is read as whole seconds only", () => {
  assert.equal(parseRetryAfter("30"), 30_000);
  assert.equal(parseRetryAfter(" 7 "), 7_000);
  assert.equal(parseRetryAfter("+5"), null);
  assert.equal(parseRetryAfter("1.5"), null);
  assert.equal(parseRetryAfter("Wed, 21 Oct 2015 07:28:00 GMT"), null);
  assert.equal(parseRetryAfter(null), null);
});

test("an absurd Retry-After is clamped, not refused", () => {
  // However many digits, it means "a long time": the clamp brings it to the
  // ceiling rather than the parser treating it as absent.
  const huge = "9".repeat(5000);
  assert.notEqual(parseRetryAfter(huge), null);
  const d = decideRetry(
    { maxElapsedMs: null, maxAttempts: null, backoffBaseMs: 200, backoffCapMs: 30_000 },
    { kind: "http", status: 503, retryAfter: huge },
    0,
    0
  );
  assert.deepEqual(d, { action: "retry", waitMs: RETRY_AFTER_MAX_MS, countsAttempt: false });
});
