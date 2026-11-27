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
 * The transport-retry policy: after a failed request to the node, wait as
 * long as the node asked, back off, or give up.
 *
 * Every client of a node or of the issuance service applies the following rules
 * identically. Two clients that decided differently would turn a node's planned
 * pause — a restart, an outbox it cannot write — into one client's lost
 * submission.
 *
 * - `Retry-After` is read as a whole number of seconds only.
 * - A `Retry-After` the node sends with 503 or 429 is honored exactly
 *   (clamped to 1 s – 15 min) and is NOT a failed attempt.
 * - Everything else retryable is a counted attempt with full-jitter backoff.
 * - An attempt limit applies only when the caller sets one.
 * - Retrying ends on a TIME budget (default 120 s), not a count of quick
 *   failures: a node that restarts in 20 s is waited out, however many times
 *   the connection was refused meanwhile.
 * - A 4xx other than 408/425/429 is about the request, not the transport,
 *   and is handed back rather than retried.
 */

/** The policy a client runs under. `null` = no limit. */
export interface RetryPolicy {
  maxElapsedMs: number | null;
  maxAttempts: number | null;
  backoffBaseMs: number;
  backoffCapMs: number;
}

/** What a client does when the caller configures nothing. */
export const RETRY_DEFAULTS: Readonly<RetryPolicy> = Object.freeze({
  maxElapsedMs: 120_000,
  maxAttempts: null,
  backoffBaseMs: 200,
  backoffCapMs: 30_000,
});

/** Bounds on an honored `Retry-After`. */
export const RETRY_AFTER_MIN_MS = 1_000;
export const RETRY_AFTER_MAX_MS = 900_000;

/** One failed request, as the policy sees it. */
export type TransportOutcome =
  | { kind: "transport" }
  | { kind: "http"; status: number; retryAfter?: string | null };

/** What to do next. A backoff reports its ceiling; the wait is a draw under it. */
export type RetryDecision =
  | { action: "return" }
  | { action: "give_up" }
  | { action: "retry"; waitMs: number; countsAttempt: false }
  | { action: "retry"; waitMsMax: number; countsAttempt: true };

/**
 * Reads a whole number of seconds, trimmed, and returns milliseconds. Anything else — an
 * HTTP date, a sign, a fraction, text — is treated as absent.
 */
export function parseRetryAfter(raw: string | null | undefined): number | null {
  if (raw == null) return null;
  const t = raw.trim();
  if (!/^[0-9]+$/.test(t)) return null;
  // Past MAX_SAFE_INTEGER it is still "as long as anyone could mean": the clamp
  // brings it down to the ceiling.
  const secs = Number(t);
  return Number.isFinite(secs) ? secs * 1000 : Number.MAX_SAFE_INTEGER;
}

function isTransient(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599);
}

/**
 * The decision after one failure. `countedBefore` is the number
 * of counted attempts before this failure; `elapsedMs` the time since the
 * first attempt.
 */
export function decideRetry(
  policy: RetryPolicy,
  outcome: TransportOutcome,
  countedBefore: number,
  elapsedMs: number
): RetryDecision {
  if (outcome.kind === "http" && !isTransient(outcome.status)) return { action: "return" };
  if (policy.maxElapsedMs !== null && elapsedMs >= policy.maxElapsedMs) {
    return { action: "give_up" };
  }
  if (outcome.kind === "http" && (outcome.status === 503 || outcome.status === 429)) {
    const asked = parseRetryAfter(outcome.retryAfter);
    if (asked !== null) {
      const waitMs = Math.min(Math.max(asked, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS);
      if (policy.maxElapsedMs !== null && elapsedMs + waitMs > policy.maxElapsedMs) {
        return { action: "give_up" }; // A shorter wait cannot succeed.
      }
      return { action: "retry", waitMs, countsAttempt: false };
    }
  }
  const n = countedBefore + 1;
  if (policy.maxAttempts !== null && n >= policy.maxAttempts) return { action: "give_up" };
  let waitMsMax = Math.min(policy.backoffCapMs, policy.backoffBaseMs * 2 ** (n - 1));
  if (policy.maxElapsedMs !== null) {
    waitMsMax = Math.min(waitMsMax, policy.maxElapsedMs - elapsedMs); // Never exceed the time budget.
  }
  return { action: "retry", waitMsMax, countsAttempt: true };
}

/** A full-jitter draw under a backoff ceiling. */
export function drawBackoffMs(waitMsMax: number): number {
  // Uniform over the WHOLE window: under a thundering herd the halved variant
  // leaves every client's retries clustered in the back half, colliding again.
  return Math.floor(Math.random() * (waitMsMax + 1));
}
