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
 * Client for a CERTCRYPT node — the issuer-side HTTP surface this SDK talks to.
 *
 * Scope: an HTTP client over the node's issuer routes — `POST /v1/issue` and
 * `GET /v1/operations/{id}`, plus activation, emission recovery and dead
 * letters. The node wraps the submitted commitments into the
 * closed submission set and tracks the resulting operation.
 *
 * NO CUSTODY: the issuer produces a zero-data `capacity.evidence/1` (projected,
 * unlinkable) — signing only the Level-3 projected commitment with a non-reused
 * operation-key leaf — and submits it as a loose commitment (see
 * `mintVerifiableCertificate`). `issue(request)` sends commitments a caller has
 * already signed.
 */

import {
  decideRetry,
  drawBackoffMs,
  parseRetryAfter,
  RETRY_AFTER_MAX_MS,
  RETRY_AFTER_MIN_MS,
  RETRY_DEFAULTS,
  type RetryPolicy,
  type TransportOutcome,
} from "./retry.js";
import type {
  EmissionHandleRecord,
  LooseCommitment,
  IssueRequest,
  IssueResponse,
  OperationRecord,
  OperationState,
  SettlementProgress,
  SettlementWindowEstimate,
  UnresolvedEmissions,
} from "./types.js";
import {
  assembleEvidence,
  assertSubmissionSetWithinBound,
  type SignedLevel1Binding,
  type StableIdentifiers,
} from "./artifacts/capacity-evidence.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import {
  assembleBaseCertificate,
  type SubjectInput,
  type IssuerKey,
  type MintedCertificate,
  type IssuanceTarget,
} from "./artifacts/base-certificate.js";
import {
  buildCommitmentInclusionProof,
  type CommitmentInclusionProof,
} from "./artifacts/commitment-inclusion.js";

export class CertcryptNodeError extends Error {
  readonly status: number | null;
  readonly body: string | null;
  /**
   * The wait the node asked for, in ms, when it refused with 503 or 429 and a
   * usable `Retry-After` — a restart, an outbox it could not write. `null`
   * otherwise. Read by the retry policy; surfaced so a caller that gives up can
   * still tell "come back in 10 s" from "broken".
   */
  readonly retryAfterMs: number | null;
  /**
   * The machine-readable reason the node gave, when its body carries one: the
   * `error` code of a `{error, message, request_id}` answer (a request the node
   * refused before submitting it), or the whole-request `state` of an
   * `IssueResponse` (e.g. `submission_failed`). `null` otherwise.
   *
   * `integration_key_replaced` (HTTP 409, on activation): the integration key
   * in this configuration was replaced by a newer one — regenerating the key in
   * the console invalidates every previous key at once. Not retryable: update
   * the configuration with the latest integration key and start again.
   */
  readonly code: string | null;
  /**
   * For a `submission_failed` the node answered with HTTP 422: the HTTP status
   * with which the CERTCRYPT service definitively refused the request. Nothing
   * was queued; resending the same request gets the same answer, so fix the
   * cause before submitting anew. `null` otherwise.
   */
  readonly upstreamStatus: number | null;
  constructor(
    message: string,
    status: number | null,
    body: string | null,
    retryAfterMs: number | null = null
  ) {
    super(message);
    this.name = "CertcryptNodeError";
    this.status = status;
    this.body = body;
    this.retryAfterMs = retryAfterMs;
    const detail = body ? nodeErrorDetail(body) : null;
    this.code = detail?.code ?? null;
    this.upstreamStatus = detail?.upstreamStatus ?? null;
  }
}

/**
 * True for a response field that carries nothing: absent, `null`, `false`, `0`,
 * `""`, `{}` or `[]` — the set the activation answer counts as missing.
 */
function isEmptyField(v: unknown): boolean {
  if (v === undefined || v === null || v === false || v === 0 || v === "") return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === "object") return Object.keys(v as object).length === 0;
  return false;
}

/**
 * The two statuses a successful `POST /v1/activate` carries: `redeemed` on the
 * first activation, `already_consumed_same_root` on an idempotent replay with the
 * same key-set root. Any other value is not an activation.
 */
const ACTIVATION_STATUSES: ReadonlyArray<string> = ["redeemed", "already_consumed_same_root"];

/** The fields an activation answer cannot do without, in the order a refusal
 *  names them. */
const ACTIVATION_REQUIRED = [
  "level1_binding",
  "level1_signature",
  "holder_id",
  "pool_id",
] as const;

/** The required fields that must be strings, in the order a refusal names them. */
const ACTIVATION_STRINGS = ["holder_id", "pool_id"] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}

/**
 * The composite signature wire shape `level1_signature` must have: the shape the
 * binding's verifier later reads (`alg`, `mode`, and one or more component
 * signatures, each with its `alg` and `sig_b64`). The SDK carries the signature
 * verbatim into every proof it presents, so a value of any other shape would
 * only fail later, far from its cause.
 */
function isCompositeSignature(v: unknown): boolean {
  if (!isPlainObject(v)) return false;
  if (!isNonEmptyString(v.alg) || !isNonEmptyString(v.mode)) return false;
  const components = v.signatures;
  if (!Array.isArray(components) || components.length === 0) return false;
  for (const c of components) {
    if (!isPlainObject(c)) return false;
    if (!isNonEmptyString(c.alg) || !isNonEmptyString(c.sig_b64)) return false;
    if ("encoding" in c && typeof c.encoding !== "string") return false;
    if ("low_s" in c && typeof c.low_s !== "boolean") return false;
  }
  return true;
}

/** What `POST /v1/activate` returns, parsed. */
export interface ActivationResult {
  signedLevel1: SignedLevel1Binding;
  poolId: string;
  holderId: string;
  /** `redeemed` or `already_consumed_same_root`; both are success. */
  status: string;
}

/**
 * Read a `POST /v1/activate` answer, failing closed.
 *
 * Four refusals, checked in this order, each throwing `CertcryptNodeError` with
 * no HTTP status (the request itself succeeded):
 *
 *   1. the body is not a JSON object: `activate returned no JSON object`;
 *   2. a required field is absent or empty (`null`, `""`, `0`, `false`, `{}`,
 *      `[]`): `activate returned no <fields>`;
 *   3. a field has the wrong type (`level1_binding` not an object,
 *      `level1_signature` not a composite signature, `holder_id` or `pool_id`
 *      not a string):
 *      `activate returned a malformed <fields>`;
 *   4. `status` is neither `redeemed` nor `already_consumed_same_root`:
 *      `activate returned an unrecognized status`.
 *
 * The checks and their order are part of the activation contract of the
 * issuance service. Nothing is cached or persisted on a refusal: the caller adopts
 * nothing until this returns.
 */
function parseActivation(parsed: unknown): ActivationResult {
  if (!isPlainObject(parsed)) {
    throw new CertcryptNodeError("activate returned no JSON object", null, null);
  }
  const body = parsed;
  const raw = JSON.stringify(body);

  const missing = ACTIVATION_REQUIRED.filter((k) => isEmptyField(body[k]));
  if (missing.length > 0) {
    throw new CertcryptNodeError(`activate returned no ${missing.join(", ")}`, null, raw);
  }

  const malformed: string[] = [];
  if (!isPlainObject(body.level1_binding)) malformed.push("level1_binding");
  if (!isCompositeSignature(body.level1_signature)) malformed.push("level1_signature");
  for (const k of ACTIVATION_STRINGS) {
    if (typeof body[k] !== "string") malformed.push(k);
  }
  if (malformed.length > 0) {
    throw new CertcryptNodeError(`activate returned a malformed ${malformed.join(", ")}`, null, raw);
  }

  const status = body.status;
  if (typeof status !== "string" || !ACTIVATION_STATUSES.includes(status)) {
    throw new CertcryptNodeError("activate returned an unrecognized status", null, raw);
  }

  return {
    signedLevel1: {
      level1_binding: body.level1_binding,
      level1_signature: body.level1_signature,
    } as SignedLevel1Binding,
    poolId: body.pool_id as string,
    holderId: body.holder_id as string,
    status,
  };
}

/** What a node error body says, in either of its two JSON shapes. */
interface NodeErrorDetail {
  code: string;
  message: string;
  upstreamStatus: number | null;
}

/**
 * Parse a node error body: an `IssueResponse` with a whole-request `state`
 * (`{state: {state, error?, upstream_status?}}`), or the node's plain
 * `{error, message, request_id}`. `null` for anything else.
 */
function nodeErrorDetail(text: string): NodeErrorDetail | null {
  let b: unknown;
  try {
    b = JSON.parse(text);
  } catch {
    return null; // not JSON: the status says it all
  }
  if (typeof b !== "object" || b === null) return null;
  const o = b as {
    state?: { state?: unknown; error?: unknown; message?: unknown; upstream_status?: unknown };
    error?: unknown;
    message?: unknown;
  };
  if (o.state && typeof o.state.state === "string") {
    const msg =
      typeof o.state.error === "string"
        ? o.state.error
        : typeof o.state.message === "string"
          ? o.state.message
          : "";
    const up = o.state.upstream_status;
    return {
      code: o.state.state,
      message: msg,
      upstreamStatus: typeof up === "number" && Number.isInteger(up) ? up : null,
    };
  }
  if (typeof o.error === "string") {
    return {
      code: o.error,
      message: typeof o.message === "string" ? o.message : "",
      upstreamStatus: null,
    };
  }
  return null;
}

/** The node's `Retry-After`, honored only on 503 and 429. */
function retryAfterOf(resp: Response): { raw: string | null; ms: number | null } {
  // Defensive: test doubles and some fetch polyfills omit `headers`.
  const raw = resp.headers?.get?.("retry-after") ?? null;
  const honored = resp.status === 503 || resp.status === 429;
  return { raw, ms: honored ? parseRetryAfter(raw) : null };
}

/**
 * ` — <code>[ (upstream HTTP <n>)]: <message>` from a node error body, when it
 * carries one, so the caller sees WHY the node refused, not just the status.
 */
function describeState(text: string): string {
  const d = nodeErrorDetail(text);
  if (!d) return "";
  const up = d.upstreamStatus !== null ? ` (upstream HTTP ${d.upstreamStatus})` : "";
  return ` — ${d.code}${up}${d.message ? `: ${d.message}` : ""}`;
}

/** The request an issuer proof is made for: what the node binds it to. */
export interface IssuerAuthRequest {
  method: string;
  /** Absolute URL, as fetched. */
  url: string;
  /** The exact body sent, if any. */
  body?: string;
}

/** Signing domain of the issuer's per-request proof to a node. */
export const ISSUER_AUTH_DOMAIN = "certcrypt:issuer-auth:1";

/**
 * The bytes the issuer's leaf signs for `challenge` on `request`:
 * `certcrypt:issuer-auth:1|<challenge>|<host>|<METHOD> <path?query>|<sha3-256
 * hex of the body>`. The node rebuilds it from the request it receives, so a
 * proof captured in transit is good only for repeating that very request — not
 * another route, body or node. `host` is the URL's host with a non-default port.
 */
export function issuerAuthMessage(challenge: string, request: IssuerAuthRequest): string {
  const u = new URL(request.url);
  const digest = Buffer.from(
    sha3_256(new TextEncoder().encode(request.body ?? "")),
  ).toString("hex");
  return `${ISSUER_AUTH_DOMAIN}|${challenge}|${u.host}|${request.method.toUpperCase()} ${u.pathname}${u.search}|${digest}`;
}

/** A submission the node gave up delivering. */
export interface DeadLetter {
  requestId: string;
  attempts: number;
  createdAtMs: number;
  lastError: string | null;
}

export interface NodeClientOptions {
  /** Base URL of the node, e.g. `https://node.example`. */
  baseUrl: string;
  /**
   * The integration's `pool_id`, from onboarding.
   *
   * A property of THIS SDK instance, not a per-call choice: one integration is one
   * SDK instance and one pool. When set, every commitment is stamped with it and
   * no per-call `pool_id` is accepted, so an integration cannot emit outside its
   * own pool even by mistake — a commitment naming a different pool is rejected on
   * submit.
   */
  pool_id?: string;
  /** Optional fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
  /**
   * Self-verifying issuer-auth proof provider. Returns the base64(JSON) value for
   * the `x-certcrypt-issuer-auth` header (a fresh proof per call: the Level-1
   * binding + a leaf disclosure + a possession signature over a fresh challenge
   * bound to `request` — see {@link issuerAuthMessage}), or null if the issuer
   * is not yet activated. Set by the `Certcrypt` issuer.
   */
  issuerAuthProof?: (request: IssuerAuthRequest) => string | null;
  /** Builds the issuer's half of a READ chain: a Level-1 binding + a leaf
   *  signature over `certcrypt:read:2|<challenge>|<resource>` (a PRIVATE signing
   *  domain, not a public protocol id). The challenge is fresh per call and the
   *  server accepts it once, so it is called again for every attempt. The server requires it because a
   *  read carries no signed artifact of its own, so the scope must derive from who
   *  SIGNED the request rather than from whoever transported it. */
  issuerReadProof?: (resource: string) => string | null;
  /**
   * Called when a read reveals the upstream id of a node-local operation the
   * caller did not know it for — a member the node delivered after answering
   * `accepted_for_retry`. The `Certcrypt` issuer uses it to sign later reads
   * over the id the server routes on.
   */
  onUpstreamOperationId?: (operationId: string, upstreamOperationId: string) => void;
  /**
   * Retry policy for transient submit failures (timeout, 5xx, connection
   * refused, node `submission_failed`, a node restarting). Reuses the SAME
   * stable `request_id` across attempts, so the server deduplicates
   * idempotently — a retry never re-signs and never double-submits.
   * Non-retryable verdicts (rejected, insufficient_capacity, replay_detected)
   * fail fast, never retried. See `./retry.ts` for the full policy.
   */
  retry?: RetryOptions;
  /**
   * Clock and sleep, injectable for tests and simulations. Defaults: `Date.now`
   * and a `setTimeout` sleep.
   */
  /** Injected time and randomness, for tests. `random` spreads scheduled settlement checks. */
  clock?: { now: () => number; sleep: (ms: number) => Promise<void>; random?: () => number };
}

/**
 * Retry policy for transient submit failures. Retrying ends on TIME, not on a
 * count of quick failures: a node that restarts in 20 s is waited out however
 * many times the connection was refused meanwhile. A `Retry-After` the node
 * sends is honored exactly and never counted as an attempt.
 */
export interface RetryOptions {
  /** Total time budget in ms, from the first attempt. Default 120_000. */
  maxElapsedMs?: number;
  /**
   * Max COUNTED attempts (incl. the first). Default: no limit — the time budget
   * bounds the retrying. 1 disables retry.
   */
  maxAttempts?: number;
  /** Base backoff in ms (attempt n waits a draw under base*2^(n-1)). Default 200. */
  baseMs?: number;
  /** Cap on a single backoff wait in ms. Default 30_000. */
  capMs?: number;
}

/** What a poll tick is currently waiting on — reported to `onProgress`. */
export interface WaitProgress {
  /** 1-based poll number. */
  attempt: number;
  /** The node's last reported state (e.g. `processing`). */
  nodeState: string;
  /** Ms this tick will sleep before the next check. */
  nextCheckInMs: number;
  /** Total ms elapsed since the wait began. */
  elapsedMs: number;
  /** The window the node expects to settle in, when it reported one. Lets an
   *  issuer log/render "still alive, expected to close at HH:MM". */
  window?: SettlementWindowEstimate;
  /** True once the operator's `expected_settled_by` has passed (or, when the node
   *  reports no such instant, once `target_close_by` has passed) and the operation
   *  is still not terminal — the operation is running LATE. The poller has fallen
   *  back to backoff. */
  overdue: boolean;
  /** How far the settlement has come, when the operator reported it. Lets a caller
   *  tell "still queued behind a window" from "on chain, waiting for
   *  irreversibility" — the difference between a wait that has not started and one
   *  that is nearly over. Advisory: never treat `finality_pending` as evidence. */
  settlement?: SettlementProgress;
  /**
   * A ready-to-log line describing what the wait is doing and why, so an
   * integrator gets a useful message without composing one from the fields.
   * A long sleep (waiting for a window) is indistinguishable from a hang unless
   * something says so — this is that something.
   */
  message: string;
}

/** Render the human-readable line carried by {@link WaitProgress.message}. */
function describeWait(p: Omit<WaitProgress, "message">): string {
  const secs = (ms: number) => `${Math.max(1, Math.round(ms / 1000))}s`;
  const head = `still ${p.nodeState} after ${secs(p.elapsedMs)}`;
  // Once settlement is on the substrate the window is no longer what the wait is
  // about: it is the substrate's irreversibility, which no amount of window scheduling shortens.
  // Saying so is the difference between "this looks hung" and "this is nearly done".
  if (p.settlement?.phase === "finality_pending") {
    const pct =
      p.settlement.progress_ppm === undefined
        ? ""
        : ` (~${Math.floor(p.settlement.progress_ppm / 10_000)}%)`;
    return (
      `${head} — settled on chain, waiting for irreversibility${pct}; ` +
      `next check in ${secs(p.nextCheckInMs)}`
    );
  }
  if (p.overdue && p.window?.expected_settled_by) {
    return (
      `${head} — OVERDUE: settlement is past the operator's expected instant ` +
      `${p.window.expected_settled_by} (window ${p.window.window_profile}); ` +
      `retrying in ${secs(p.nextCheckInMs)}`
    );
  }
  if (p.window?.expected_settled_by) {
    const close = p.window.target_close_by ? ` to close (~${p.window.target_close_by})` : "";
    return (
      `${head} — waiting for settlement window ${p.window.window_profile}${close}, ` +
      `settlement expected by ~${p.window.expected_settled_by}; next check in ${secs(p.nextCheckInMs)}`
    );
  }
  if (p.overdue && p.window?.target_close_by) {
    return (
      `${head} — OVERDUE: window ${p.window.window_profile} was due to close by ` +
      `${p.window.target_close_by}; retrying in ${secs(p.nextCheckInMs)}`
    );
  }
  if (p.window?.target_close_by) {
    return (
      `${head} — waiting for settlement window ${p.window.window_profile} to close ` +
      `(~${p.window.target_close_by}); next check in ${secs(p.nextCheckInMs)}`
    );
  }
  if (p.window) {
    return (
      `${head} — window ${p.window.window_profile} assigned, no close estimate yet; ` +
      `next check in ${secs(p.nextCheckInMs)}`
    );
  }
  return `${head} — no window estimate from the node; next check in ${secs(p.nextCheckInMs)}`;
}

export interface WaitOptions {
  /**
   * Fixed poll interval in ms. Setting it selects the fixed-interval strategy
   * (see `strategy`).
   */
  intervalMs?: number;
  /** Max attempts before giving up (default 60 in fixed-interval mode). */
  maxAttempts?: number;
  /**
   * How to space the polls. Default `"auto"`:
   *   - if the node reports when it expects the settlement to be final, sleep
   *     UNTIL `expected_settled_by` (plus a small clock-skew margin) and check once
   *     on arrival;
   *   - else, if it reports only the window's close, sleep until `target_close_by`
   *     (plus a small settling margin);
   *   - otherwise, exponential backoff with a cap.
   * `"fixed"` polls every `intervalMs`.
   *
   * Defaults to `"fixed"` when `intervalMs` or `maxAttempts` is supplied.
   */
  strategy?: "auto" | "fixed";
  /**
   * Wall-clock bound on the whole wait. This is what an integrator actually knows
   * how to express — `maxAttempts` only means something once you also know the
   * interval. When both are given, whichever trips first ends the wait.
   * Default in `auto` mode: 15 minutes.
   */
  maxWaitMs?: number;
  /** First backoff step in ms when there is no window estimate (default 1000). */
  backoffBaseMs?: number;
  /** Cap on a single backoff sleep in ms (default 30_000). */
  backoffCapMs?: number;
  /**
   * Called before each sleep, so the issuer can log or render that the operation
   * is alive and which window it is waiting on. Never throws into the poll: an
   * exception from the callback is swallowed.
   */
  onProgress?: (p: WaitProgress) => void;
}

/**
 * Extra delay after `target_close_by` before checking, when the node reports no
 * `expected_settled_by`. The target is the window's CLOSE, but the package only
 * exists once the settlement is anchored and finality has advanced — checking at
 * the exact target reliably observes `processing` and wastes the trip.
 */
const WINDOW_SETTLING_MARGIN_MS = 3_000;

/**
 * Extra delay after `expected_settled_by` before the last scheduled check. That
 * instant already accounts for anchoring and finality, so the margin only absorbs
 * clock skew between this host and the operator.
 */
const EXPECTED_SETTLED_MARGIN_MS = 1_000;

/**
 * Where the early check sits between the close and `expected_settled_by`, as a
 * fraction of that span. The operator sets `expected_settled_by` with headroom
 * so that "overdue" means something; most settlements land well before it, and
 * one check inside the span finds them without waiting out the headroom.
 */
const SETTLEMENT_CHECKPOINT_FRACTION = 0.6;

/**
 * Every operation in a window shares its close, so their checks would otherwise
 * reach the node — and through it the operator — at the same instant. Each
 * scheduled check is pushed back by a random 0..this many ms. Only ever later,
 * never earlier, so no check lands before the instant it is aimed at.
 */
const CHECKPOINT_SPREAD_MS = 1_000;

/**
 * Upper bound on ONE sleep towards a scheduled check. The backoff cap is far too
 * short for this: a window that closes in three minutes would otherwise be polled
 * every 30 s while it is still open, for nothing. This bound only exists so that a
 * mis-set instant cannot park the poller indefinitely; the whole wait is still
 * bounded by `maxWaitMs`.
 */
const SCHEDULED_SLEEP_CAP_MS = 10 * 60_000;

/**
 * The checks a wait schedules for a window, in order, and the instant after which
 * a still-pending operation is overdue.
 *
 * With `expected_settled_by` (E) and `target_close_by` (T): one check at
 * T + 60 % of (E − T), one at E + 1 s; overdue past E. With only T: one check at
 * T + 3 s; overdue past T. With only E: one check at E + 1 s. Neither (or neither
 * parses): no checks, `dueMs` NaN.
 */
function windowCheckpoints(window: SettlementWindowEstimate | undefined): {
  checkpoints: number[];
  dueMs: number;
} {
  const target = window?.target_close_by ? Date.parse(window.target_close_by) : NaN;
  const expected = window?.expected_settled_by ? Date.parse(window.expected_settled_by) : NaN;
  if (Number.isFinite(expected)) {
    // The operator never reports settlement before the close; if it did, the
    // close is still the earlier bound on a terminal state.
    const dueMs = Number.isFinite(target) ? Math.max(expected, target) : expected;
    const checkpoints: number[] = [];
    if (Number.isFinite(target) && dueMs > target) {
      checkpoints.push(target + Math.round((dueMs - target) * SETTLEMENT_CHECKPOINT_FRACTION));
    }
    checkpoints.push(dueMs + EXPECTED_SETTLED_MARGIN_MS);
    return { checkpoints, dueMs };
  }
  if (Number.isFinite(target)) {
    return { checkpoints: [target + WINDOW_SETTLING_MARGIN_MS], dueMs: target };
  }
  return { checkpoints: [], dueMs: NaN };
}

/**
 * True when the operation is running late at `now`: the operator's
 * `expected_settled_by` has passed, or — when the node reports no such instant —
 * the window's `target_close_by` has. False when the window names neither.
 */
export function isSettlementOverdue(
  window: SettlementWindowEstimate | undefined,
  now: number
): boolean {
  const { dueMs } = windowCheckpoints(window);
  return Number.isFinite(dueMs) && now > dueMs;
}

/** Default wall-clock bound for `auto` mode. */
const DEFAULT_MAX_WAIT_MS = 15 * 60_000;

/**
 * When no `onProgress` was supplied, a sleep at least this long is announced on
 * the console. Below it the wait is short enough to read as "working"; above it,
 * silence reads as a hang.
 */
const QUIET_WAIT_WARN_MS = 10_000;

/**
 * Choose how long to sleep before the next poll.
 *
 * Exported for testing: the scheduling decision is the whole point of the
 * until-window mode, and it is far easier to pin as a pure function than through
 * a live poll loop.
 */
export function nextPollDelayMs(args: {
  attempt: number;
  now: number;
  window?: SettlementWindowEstimate;
  backoffBaseMs: number;
  backoffCapMs: number;
  /** Source of the 0..1 s spread added to a scheduled check; `Math.random` by default. */
  random?: () => number;
}): { delayMs: number; overdue: boolean } {
  const { attempt, now, window, backoffBaseMs, backoffCapMs } = args;
  const random = args.random ?? Math.random;
  const { checkpoints } = windowCheckpoints(window);
  if (checkpoints.length > 0) {
    // The next scheduled check still ahead of us: sleep straight until it (plus
    // the spread) instead of polling a window that is still open. Capped only so
    // a mis-set instant cannot park the poller indefinitely.
    const next = checkpoints.find((p) => p > now);
    if (next !== undefined) {
      const spread = Math.floor(Math.min(Math.max(random(), 0), 1) * CHECKPOINT_SPREAD_MS);
      return {
        delayMs: Math.min(next - now + spread, Math.max(SCHEDULED_SLEEP_CAP_MS, backoffCapMs)),
        overdue: false,
      };
    }
    // Every scheduled check has run and we are still not terminal: the operation
    // is running late. Fall through to backoff and SAY it is overdue.
    const backoff = Math.min(backoffBaseMs * 2 ** Math.max(0, attempt - 1), backoffCapMs);
    return { delayMs: backoff, overdue: true };
  }
  // No estimate → exponential backoff with a cap.
  const backoff = Math.min(backoffBaseMs * 2 ** Math.max(0, attempt - 1), backoffCapMs);
  return { delayMs: backoff, overdue: false };
}

/** A `verification_package` (verification-package/1): one object with a closed member
 *  set, read by an offline verifier in package mode. `base_certificate` and
 *  `verification_context` are always present; nothing outside these members is. */
export interface VerificationPackage {
  base_certificate: unknown;
  independence_proof: unknown;
  verification_context: { rules_version: string; system_id: string };
  capacity_evidence?: unknown;
  commitment_inclusion_proof?: CommitmentInclusionProof;
  settlement_material?: unknown;
  settlement_reference?: string;
}

/** Client-held inputs for `buildVerificationPackage` — the two artifacts the
 *  issuer produces locally (never returned by the node) plus the context. */
export interface BuildPackageOptions {
  /** The signed base_certificate from `mintVerifiableCertificate().minted`. */
  baseCertificate: unknown;
  /** The `capacity.evidence/1` from the issue call's `commitment.capacity_evidence`. */
  capacityEvidence: unknown;
  /** Published profile values (issuer config: CERTCRYPT_RULES_VERSION + system id). */
  verificationContext: { rules_version: string; system_id: string };
  /** This commitment's index in the accepted set (MemberResult.commitment_index). */
  commitmentIndex: number;
  /** Poll options while awaiting independent_ready. */
  wait?: WaitOptions;
}

/**
 * Verdicts the client must NOT re-POST. Everything else transient (timeout,
 * transport error, `submission_failed`) is retryable.
 *
 * `accepted_for_retry` is here on purpose: the submission did not get through on
 * this attempt, but the node has taken durable custody of it and will deliver it.
 * Re-POSTing would be wasted work, and worse, it invites a duplicate. The eventual
 * outcome is observed by polling the operation, not by re-issuing.
 */
function isNonRetryableState(state: string): boolean {
  return (
    state === "independent_ready" ||
    state === "accepted" ||
    state === "accepted_for_retry" ||
    state === "rejected" ||
    state === "expired" ||
    state === "insufficient_capacity" ||
    state === "replay_detected" ||
    // The node sends a rejection before per-member evaluation with HTTP 200;
    // resending the same set gets the same answer.
    state === "pre_evaluation_rejected"
  );
}

/** Sleep helper. */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Generate a 26-char ULID (Crockford base32): 48-bit millisecond timestamp +
 * 80-bit randomness. The server's idempotency key MUST be a ULID (26 chars), NOT a
 * UUID (36 chars) — `crypto.randomUUID()` would be rejected with HTTP 400.
 */
const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32 (no I,L,O,U)
function newUlid(): string {
  let ts = Date.now();
  const time = new Array<string>(10);
  for (let i = 9; i >= 0; i--) {
    time[i] = ULID_ALPHABET[ts % 32]!;
    ts = Math.floor(ts / 32);
  }
  const rand = new Uint8Array(16);
  globalThis.crypto.getRandomValues(rand);
  let out = time.join("");
  for (let i = 0; i < 16; i++) out += ULID_ALPHABET[rand[i]! % 32]!;
  return out; // 10 (time) + 16 (rand) = 26 chars
}

/** Exponential backoff with full jitter for attempt `n` (1-based). */
function backoffMs(n: number, baseMs: number, capMs: number): number {
  // Polling backoff (waitForOperation). Submit retries use `decideRetry`.
  const exp = Math.min(capMs, baseMs * 2 ** (n - 1));
  // Full jitter: a uniform draw over the WHOLE window, not `exp/2 + rand(exp/2)`.
  // Under a thundering herd the halved variant leaves every client's retries clustered in
  // the back half of the window and they collide again; drawing over the full window is
  // what actually spreads them.
  return Math.floor(Math.random() * exp);
}

/** The states from which an operation will not move on its own. */
const TERMINAL_STATES: ReadonlySet<string> = new Set([
  "independent_ready",
  "rejected",
  "expired",
  "replay_detected",
  "insufficient_capacity",
  "pre_evaluation_rejected",
  "submission_failed",
]);

/**
 * True for a terminal state name: polling stops there. `accepted_for_retry` and
 * `accepted` are not terminal — the first means the node holds the set and will
 * deliver it, the second that a member was accepted for processing, not settled.
 */
export function isTerminalState(state: string): boolean {
  return TERMINAL_STATES.has(state);
}

function isTerminal(state: OperationState): boolean {
  return isTerminalState(state.state);
}

/**
 * Normalize the two shapes `GET /v1/operations/{id}` can return into one
 * OperationRecord (see the type doc). A local node record already carries
 * `state`; the server body forwarded on reconciliation carries `status` (string)
 * plus the base64 proof artifacts and no `state`/`request_id`. We map that
 * `status` to a `state` discriminant and surface the proof fields.
 */
function normalizeOperationRecord(body: Record<string, unknown>): OperationRecord {
  const operation_id = String(body.operation_id ?? "");
  const independence_proof =
    typeof body.independence_proof === "string" ? body.independence_proof : undefined;
  const settlement_material =
    typeof body.settlement_material === "string" ? body.settlement_material : undefined;
  // The scheduling hint, present while the operation is being settled. Read defensively:
  // a node that does not send it is fully supported, and the poller simply falls
  // back to backoff. We copy ONLY the known scheduling
  // fields — never spread the object — so that if the wire ever grew a cost-like
  // field it could not silently reach an SDK consumer or its logs.
  const sw = body.settlement_window;
  let settlement_window: SettlementWindowEstimate | undefined;
  if (sw && typeof sw === "object") {
    const w = sw as Record<string, unknown>;
    if (typeof w.window_profile === "string" && typeof w.window_profile_version === "string") {
      settlement_window = {
        window_profile: w.window_profile,
        window_profile_version: w.window_profile_version,
        ...(typeof w.target_close_by === "string"
          ? { target_close_by: w.target_close_by }
          : {}),
        ...(typeof w.expected_settled_by === "string"
          ? { expected_settled_by: w.expected_settled_by }
          : {}),
      };
    }
  }

  // The progress indicator, same defensive discipline as the window above and for
  // the same reason: copy ONLY the three known fields, never spread. The wire could
  // grow a substrate-revealing field (a block height, a finality lag) and spreading would
  // hand it to an SDK consumer and its logs without anyone deciding to.
  const sp = body.settlement_progress;
  let settlement_progress: SettlementProgress | undefined;
  if (sp && typeof sp === "object") {
    const g = sp as Record<string, unknown>;
    if (typeof g.phase === "string") {
      settlement_progress = {
        phase: g.phase,
        ...(typeof g.progress_ppm === "number" ? { progress_ppm: g.progress_ppm } : {}),
        ...(typeof g.observed_at === "string" ? { observed_at: g.observed_at } : {}),
      };
    }
  }

  // Already in node-record shape (has a structured `state`): pass through.
  if (body.state && typeof body.state === "object") {
    return {
      operation_id,
      request_id: typeof body.request_id === "string" ? body.request_id : undefined,
      state: body.state as OperationState,
      ...(independence_proof ? { independence_proof } : {}),
      ...(settlement_material ? { settlement_material } : {}),
      ...(settlement_window ? { settlement_window } : {}),
      ...(settlement_progress ? { settlement_progress } : {}),
    };
  }

  // Server body shape: `status` string → map to a state discriminant.
  //
  // AN ACCEPTED OPERATION CAN STILL END WITHOUT A PROOF. The CERTCRYPT service
  // answers one of five statuses — processing, independent_ready, rejected,
  // insufficient_capacity, expired. An operation can be rejected after it was
  // accepted (e.g. a window whose settlement could not be proven), or expire: its
  // authorization ran out before it could settle, nothing was consumed
  // (submission-set/1 §11.1). Folding either into `processing` would leave
  // `waitForOperation` polling indefinitely, so every known terminal status is
  // mapped explicitly.
  //
  // Only an unrecognized status falls back to `processing`, so the poller keeps
  // going rather than inventing a terminal state.
  const status = String(body.status ?? "processing");
  const reasonCode = typeof body.reason_code === "string" ? body.reason_code : status;
  const message = typeof body.message === "string" ? body.message : "";
  const state: OperationState =
    status === "independent_ready"
      ? { state: "independent_ready", upstream_operation_id: operation_id }
      : status === "rejected"
        ? { state: "rejected", reason_code: reasonCode, message }
        : status === "insufficient_capacity"
          ? { state: "insufficient_capacity" }
          : status === "expired"
            ? { state: "expired", reason_code: reasonCode, message }
            : { state: "processing", upstream_operation_id: operation_id };

  return {
    operation_id,
    state,
    ...(independence_proof ? { independence_proof } : {}),
    ...(settlement_material ? { settlement_material } : {}),
    ...(settlement_window ? { settlement_window } : {}),
    ...(settlement_progress ? { settlement_progress } : {}),
  };
}

/**
 * How long every request (issue, activate, reads, health) waits for the
 * node before giving up on that attempt, in ms: 30 s. An attempt that times out
 * is a transport failure, retried under the transport-retry policy where the
 * request is retried at all.
 */
export const REQUEST_TIMEOUT_MS = 30_000;

/** The body of a 2xx `/v1/issue` answer that is not a JSON object. */
class UnparseableIssueResponse extends Error {
  constructor(readonly status: number, readonly text: string) {
    super("issue failed: unparseable node response");
  }
}

export class CertcryptNodeClient {
  /** The node base URL every request goes to, without a trailing slash. */
  readonly baseUrl: string;
  private readonly poolId: string | null;
  private readonly fetchImpl: typeof fetch;
  private readonly retryPolicy: RetryPolicy;
  private readonly now: () => number;
  private readonly sleepMs: (ms: number) => Promise<void>;
  private readonly random: () => number;
  private readonly issuerAuthProof: ((request: IssuerAuthRequest) => string | null) | null;
  private readonly issuerReadProof: ((resource: string) => string | null) | null;
  private readonly onUpstreamOperationId:
    | ((operationId: string, upstreamOperationId: string) => void)
    | null;

  constructor(opts: NodeClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.poolId = opts.pool_id ?? null;
    this.retryPolicy = {
      maxElapsedMs: opts.retry?.maxElapsedMs ?? RETRY_DEFAULTS.maxElapsedMs,
      maxAttempts:
        opts.retry?.maxAttempts !== undefined
          ? Math.max(1, opts.retry.maxAttempts)
          : RETRY_DEFAULTS.maxAttempts,
      backoffBaseMs: opts.retry?.baseMs ?? RETRY_DEFAULTS.backoffBaseMs,
      backoffCapMs: opts.retry?.capMs ?? RETRY_DEFAULTS.backoffCapMs,
    };
    this.now = opts.clock?.now ?? (() => Date.now());
    this.sleepMs = opts.clock?.sleep ?? sleep;
    this.random = opts.clock?.random ?? Math.random;
    this.issuerAuthProof = opts.issuerAuthProof ?? null;
    this.issuerReadProof = opts.issuerReadProof ?? null;
    this.onUpstreamOperationId = opts.onUpstreamOperationId ?? null;
    const f = opts.fetch ?? globalThis.fetch;
    if (!f) {
      throw new CertcryptNodeError(
        "no fetch implementation available; pass opts.fetch on older runtimes",
        null,
        null
      );
    }
    this.fetchImpl = f;
  }

  /**
   * Headers for authenticated requests (issue, operations, emission lookups,
   * dead letters). `/health` and `/v1/activate` need
   * no issuer proof.
   *
   * Zero-trust auth: the node authenticates an issuer ONLY by the self-verifying
   * proof in `x-certcrypt-issuer-auth` — the system-domain-signed binding over the
   * holder_key_set_root + a leaf disclosure + a possession signature over a fresh
   * challenge, built anew for every request. The node verifies it offline, with
   * no token lookup. No `Authorization` header is sent: the node would ignore it,
   * and a bearer credential handed to a node buys nothing but exposure. Your scope
   * derives from the proof, never from the request body.
   */
  private authHeaders(
    request: IssuerAuthRequest,
    extra?: Record<string, string>,
  ): Record<string, string> {
    const h: Record<string, string> = { ...extra };
    if (this.issuerAuthProof) {
      const proof = this.issuerAuthProof(request);
      if (proof) h["x-certcrypt-issuer-auth"] = proof;
    }
    return h;
  }

  /**
   * One fetch bounded by {@link REQUEST_TIMEOUT_MS}: a node that accepts the
   * connection and never answers must not hold the caller forever. The timeout
   * surfaces as a rejected promise, which every caller treats as a transport
   * failure.
   */
  private async fetchWithTimeout(url: string, init: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  /** The issuer's half of a read chain over `resource`, minted anew on every call
   *  (its challenge is single-use). Empty before activation. */
  private issuerReadHeaders(resource: string): Record<string, string> {
    const proof = this.issuerReadProof ? this.issuerReadProof(resource) : null;
    return proof ? { "x-certcrypt-issuer-read": proof } : {};
  }

  /**
   * A GET under the transport-retry policy, the same decisions `issue()` makes:
   * a transport failure or a retryable status (408, 425, 429, 5xx) is retried
   * until the time budget runs out, a `Retry-After` on 503/429 is honored
   * without counting as an attempt, and any other answer is returned for the
   * caller to read. Safe because a read changes nothing.
   *
   * Returns the response's status, body and `Retry-After`; throws only when it
   * gives up, naming `label` and how long it tried.
   */
  private async readWithRetry(
    url: string,
    extraHeaders: () => Record<string, string>,
    label: string
  ): Promise<{ status: number; ok: boolean; text: string; retryAfterMs: number | null }> {
    const startedAt = this.now();
    let counted = 0;
    for (;;) {
      let outcome: TransportOutcome;
      let last: CertcryptNodeError;
      try {
        // Fresh proofs per ATTEMPT: the node accepts an auth challenge once and
        // the issuance service a read challenge once, so reusing the first
        // attempt's headers would turn every retry that got through into a 401.
        const headers = this.authHeaders({ method: "GET", url }, extraHeaders());
        const resp = await this.fetchWithTimeout(url, { headers });
        const text = await resp.text();
        const retryAfter = retryAfterOf(resp);
        if (resp.ok) return { status: resp.status, ok: true, text, retryAfterMs: null };
        outcome = { kind: "http", status: resp.status, retryAfter: retryAfter.raw };
        last = new CertcryptNodeError(
          `${label} failed: HTTP ${resp.status}`,
          resp.status,
          text,
          retryAfter.ms
        );
      } catch (e) {
        outcome = { kind: "transport" };
        last = new CertcryptNodeError(`${label} failed: ${String(e)}`, null, null);
      }
      const d = decideRetry(this.retryPolicy, outcome, counted, this.now() - startedAt);
      if (d.action === "return") {
        // About the request, not the transport: hand the answer back as it came.
        return { status: last.status ?? 0, ok: false, text: last.body ?? "", retryAfterMs: last.retryAfterMs };
      }
      if (d.action === "give_up") {
        throw new CertcryptNodeError(
          `${last.message} — gave up after ${Math.round((this.now() - startedAt) / 1000)}s ` +
            `and ${counted + 1} attempt(s)`,
          last.status,
          last.body,
          last.retryAfterMs
        );
      }
      if (d.countsAttempt) {
        counted += 1;
        await this.sleepMs(drawBackoffMs(d.waitMsMax));
      } else {
        await this.sleepMs(d.waitMs);
      }
    }
  }

  /**
   * Liveness check. True when the node answers /health with a 2xx.
   *
   * One request, never retried, bounded at 30 s, and it never throws: a
   * transport failure (refused, reset, no answer in time) and an error status
   * both report false. A liveness probe that waited out a restart would report
   * the node alive minutes late instead of reporting it down.
   */
  async health(): Promise<boolean> {
    try {
      const resp = await this.fetchWithTimeout(`${this.baseUrl}/health`);
      return resp.ok;
    } catch {
      return false;
    }
  }

  /**
   * Submit a closed submission set for issuance. Returns the node-local
   * operation and its initial state. The happy path is `processing`
   * (finalization is asynchronous); poll [`getOperation`] /
   * [`waitForOperation`].
   *
   * More than `MAX_SUBMISSION_SET_MEMBERS` (64) commitments throw
   * `SubmissionSetTooLargeError` before anything is sent (submission-set/1 §8.1).
   */
  async issue(req: IssueRequest): Promise<IssueResponse> {
    // The producer refuses to build an over-bound set (submission-set/1 §8.1):
    // fail fast, before the request leaves the process. The node and the
    // submit endpoint reject one independently.
    assertSubmissionSetWithinBound(req.commitments?.length ?? 0);
    // Stable idempotency key: generate ONCE here if the caller didn't, and reuse
    // the SAME id across every retry. The server deduplicates on it (a
    // replay returns the original outcome), so a retry never double-submits. If we let the node generate it
    // (its fallback), each retry would get a NEW id → not idempotent. The signed
    // evidence inside `req` is built once and reused verbatim on every attempt —
    // a retry is transport-only, it NEVER re-signs: a leaf must not be reused.
    const idemReq: IssueRequest = {
      ...req,
      request_id: req.request_id ?? newUlid(),
    };

    const startedAt = this.now();
    let counted = 0;
    for (;;) {
      let outcome: TransportOutcome;
      let last: CertcryptNodeError;
      try {
        const attempt = await this.issueOnce(idemReq);
        if (attempt.ok) {
          // Decide retryable vs final from the per-member results (or whole-request
          // state). A response with any non-final member is retryable; otherwise
          // return it — `accepted_for_retry` included: the node holds the set.
          if (this.isResponseFinal(attempt.body)) return attempt.body;
          outcome = { kind: "transport" };
          last = new CertcryptNodeError(
            `issue not final (retryable): ${JSON.stringify(attempt.body.state ?? attempt.body.results)}`,
            attempt.status,
            attempt.text
          );
        } else {
          outcome = { kind: "http", status: attempt.status, retryAfter: attempt.retryAfter.raw };
          last = new CertcryptNodeError(
            `issue failed: HTTP ${attempt.status}${describeState(attempt.text)}`,
            attempt.status,
            attempt.text,
            attempt.retryAfter.ms
          );
        }
      } catch (e) {
        if (e instanceof UnparseableIssueResponse) {
          // A 2xx whose body is not a JSON object: the answer was lost on the
          // way, not given. Retrying is safe — the request is idempotent on its
          // request_id, so the node answers the same set the same way.
          outcome = { kind: "transport" };
          last = new CertcryptNodeError(e.message, e.status, e.text);
        } else {
          // No HTTP answer at all: refused, reset, timed out — the node restarting.
          outcome = { kind: "transport" };
          last = new CertcryptNodeError(`issue failed: ${String(e)}`, null, null);
        }
      }

      const d = decideRetry(this.retryPolicy, outcome, counted, this.now() - startedAt);
      if (d.action === "return") throw last; // about the request, not the transport
      if (d.action === "give_up") {
        throw new CertcryptNodeError(
          `${last.message} — gave up after ${Math.round((this.now() - startedAt) / 1000)}s ` +
            `and ${counted + 1} attempt(s)`,
          last.status,
          last.body,
          last.retryAfterMs
        );
      }
      if (d.countsAttempt) {
        counted += 1;
        await this.sleepMs(drawBackoffMs(d.waitMsMax));
      } else {
        await this.sleepMs(d.waitMs);
      }
    }
  }

  /** One POST attempt. Throws on transport error; returns status, body and the
   *  node's `Retry-After`. */
  private async issueOnce(req: IssueRequest): Promise<{
    ok: boolean;
    status: number;
    text: string;
    body: IssueResponse;
    retryAfter: { raw: string | null; ms: number | null };
  }> {
    const url = `${this.baseUrl}/v1/issue`;
    const payload = JSON.stringify(req);
    const resp = await this.fetchWithTimeout(url, {
      method: "POST",
      headers: this.authHeaders(
        { method: "POST", url, body: payload },
        { "content-type": "application/json" },
      ),
      body: payload,
    });
    const text = await resp.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    const isObject = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
    if (resp.ok && !isObject) throw new UnparseableIssueResponse(resp.status, text);
    const body = (isObject ? parsed : {}) as IssueResponse;
    return { ok: resp.ok, status: resp.status, text, body, retryAfter: retryAfterOf(resp) };
  }

  /**
   * A response is FINAL (stop retrying) when every member reached a terminal
   * verdict and there is no whole-request transient failure. A whole-request
   * `submission_failed` (the node could not reach the server) is retryable.
   */
  private isResponseFinal(res: IssueResponse): boolean {
    if (res.state && res.state.state === "submission_failed") return false;
    if (res.state) return isNonRetryableState(res.state.state);
    if (res.results && res.results.length > 0) {
      return res.results.every((m) => isNonRetryableState(m.state.state));
    }
    // No state and no results: treat as retryable (incomplete).
    return false;
  }

  /**
   * Convenience: issue 1..N already-built loose commitments in one call, under a
   * request_id this client generates. The node wraps them into one submission-set. All
   * commitments MUST share issuer + authorization. Use for a batch the
   * caller already has signed on hand (e.g. a nightly import).
   */
  async issueCommitments(commitments: LooseCommitment[]): Promise<IssueResponse> {
    return this.issue({ commitments });
  }

  /**
   * Activate an integration by redeeming a one-time activation code (OTP, TOFU).
   * The node forwards this to the server's `POST /v1/activate`; the server redeems the
   * code, mints the Level-1 authorization over `holderKeySetRoot`, and returns
   * the signed binding INLINE. The caller (usually `Certcrypt`) caches the
   * returned binding as its `signedLevel1` and stops presenting the code.
   *
   * The SDK talks ONLY to the node; this is the node route, not the server.
   * `rulesVersion` and `systemRootFingerprint` come from the issuer's onboarding
   * config (the server validates the fingerprint matches its own domain).
   */
  async activate(params: {
    code: string;
    holderKeySetRoot: string;
    /** A leaf of `holderKeySetRoot` + its inclusion path. Proves the root is ours
     *  and not one a transporting node substituted. */
    keySetDisclosure: unknown;
    /** Base64 ML-DSA signature by that leaf over
     *  `certcrypt:activate:1|<code>|<holderKeySetRoot>`. */
    keySetPossessionB64: string;
    rulesVersion: string;
    systemRootFingerprint: string;
    validUntil: string;
  }): Promise<ActivationResult> {
    const url = `${this.baseUrl}/v1/activate`;
    const body = JSON.stringify({
        code: params.code,
        holder_key_set_root: params.holderKeySetRoot,
        key_set_disclosure: params.keySetDisclosure,
        key_set_possession_b64: params.keySetPossessionB64,
        rules_version: params.rulesVersion,
        system_root_fingerprint: params.systemRootFingerprint,
        valid_until: params.validUntil,
    });
    const resp = await this.fetchWithTimeout(url, {
      method: "POST",
      headers: this.authHeaders({ method: "POST", url, body }, { "content-type": "application/json" }),
      body,
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new CertcryptNodeError(
        `activate failed: HTTP ${resp.status}${describeState(text)}`,
        resp.status,
        text,
        retryAfterOf(resp).ms,
      );
    }
    // The server binds the integration's canonical (holder_id, pool_id) at
    // activation and echoes both here (relayed verbatim by the node). The caller
    // MUST emit under this holder_id: it is the identity the activation bound, and
    // emitting under a self-chosen one would not be accounted for against this
    // integration at all.
    //
    // Fail closed: a 200 that is not an activation (not an object, a field
    // missing or of the wrong type, a status other than the two successes) is
    // refused before anything is returned, so nothing is cached or persisted.
    const text = await resp.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    return parseActivation(parsed);
  }

  /**
   * Mint + sign one verifiable certificate and its loose commitment WITHOUT
   * sending anything: the ONE place a certificate is minted and signed.
   *
   * Exists so N certificates can be prepared and then submitted in ONE `issue()`
   * request (grouping amortizes the per-submission overhead across all N).
   * Synchronous: no request is made, nothing is awaited.
   *
   * Everything irreversible happens HERE — the base_certificate is signed and
   * `leafIndex`/`operationSalt` are spent. A commitment that is minted and never
   * sent leaves its leaf spent; a retry re-sends this exact commitment rather than
   * minting a new one.
   */
  mintVerifiableCertificate(params: {
    subjects: SubjectInput[];
    issuerKey: IssuerKey;
    target: IssuanceTarget;
    anchor: {
      issued_at: string;
      nonce_hex: string;
      system_id: string;
      rules_version: string;
    };
    signedLevel1: SignedLevel1Binding;
    holderId: string;
    /**
     * The pool to stamp, when the caller resolved it after this client was
     * built (the `Certcrypt` issuer learns it at activation). Defaults to the
     * client's configured `pool_id`. A client configured with a pool refuses any
     * other: one integration is one pool.
     */
    poolId?: string;
    authorizationId: string;
    evidenceFields: {
      consumed_quantity: string;
      declared_effective_units: string;
      issued_at: string;
      expires_at: string;
    };
    keySet: HolderKeySet;
    leafIndex: number;
    operationSalt: Uint8Array;
  }): { commitment: LooseCommitment; minted: MintedCertificate } {
    // 1. Mint + sign the base_certificate from the subjects' original material.
    //    The target choice decides whether the anchor carries root_id (the signed
    //    participation reference). issued-only omits it consciously; independent-
    //    capable requires it — a defaulted omission can never be repaired later.
    const rootIdField =
      params.target.mode === "independent-capable"
        ? { root_id: params.target.root_id }
        : {};
    const minted = assembleBaseCertificate({
      subjects: params.subjects,
      nonce_hex: params.anchor.nonce_hex,
      issued_at: params.anchor.issued_at,
      ...rootIdField,
      system_id: params.anchor.system_id,
      rules_version: params.anchor.rules_version,
      issuerKey: params.issuerKey,
    });

    // 2. Sign the zero-data evidence over the REAL cert digest (never an opaque
    //    string of unknown origin). The holder signs only the Level-3 projected
    //    commitment with a non-reused leaf of its operation-key tree; the Level-1
    //    anchor (`signedLevel1`) comes from the holder-authorization endpoint and
    //    is carried verbatim.
    if (this.poolId && params.poolId && params.poolId !== this.poolId) {
      throw new CertcryptNodeError(
        `mintVerifiableCertificate: pool "${params.poolId}" is not this client's ` +
          `pool "${this.poolId}" (one integration = one pool)`,
        null,
        null,
      );
    }
    const poolId = params.poolId ?? this.poolId;
    if (!poolId) {
      throw new CertcryptNodeError(
        "mintVerifiableCertificate requires a pool_id, in NodeClientOptions or as " +
          "poolId (the integration's pool; one integration = one pool)",
        null,
        null,
      );
    }
    const evidence = assembleEvidence({
      signedLevel1: params.signedLevel1,
      certificate_commitment_digest: minted.certificate_commitment_digest,
      consumed_quantity: params.evidenceFields.consumed_quantity,
      declared_effective_units: params.evidenceFields.declared_effective_units,
      issued_at: params.evidenceFields.issued_at,
      expires_at: params.evidenceFields.expires_at,
      // `pool_id` is the instance's configured pool, stamped into both the
      // operative context and the projected pool pseudonym — never chosen per call.
      stable: {
        holder_id: params.holderId,
        pool_id: poolId,
        authorization_id: params.authorizationId,
      },
      keySet: params.keySet,
      leafIndex: params.leafIndex,
      operationSalt: params.operationSalt,
    });
    // The SDK is thin: ship the signed evidence as ONE loose commitment. The node
    // is the builder that wraps it into the submission-set.
    const commitment: LooseCommitment = {
      capacity_evidence: evidence,
      operative: { holder_id: params.holderId, pool_id: poolId },
    };
    return { commitment, minted };
  }

  /**
   * Read one emission by the digest of the capacity evidence that produced it.
   *
   * The lookup that outlives the node. A node's operation id lives in THAT node's
   * journal, so a restart with an in-memory journal — or moving to another node,
   * which the model treats as changing a URL — leaves the issuer unable to ask
   * about an emission the issuance service still holds. The digest has no such
   * problem: the issuer recomputes it from evidence it signed itself.
   *
   * The read chain is unchanged, and the signed resource is the digest. That is
   * stronger than signing an id the node handed over: the issuer can check what
   * the digest means, because it produced it.
   */
  async getEmissionByCommitment(independenceRef: string): Promise<EmissionHandleRecord> {
    // No id translation here, unlike getOperation: the digest IS the resource
    // the issuance service routes and verifies on.
    const resp = await this.readWithRetry(
      `${this.baseUrl}/v1/emissions/by-commitment/${encodeURIComponent(independenceRef)}`,
      () => this.issuerReadHeaders(independenceRef),
      "getEmissionByCommitment"
    );
    if (resp.status === 404) {
      throw new CertcryptNodeError(
        `no emission for capacity-evidence digest ${independenceRef}`,
        404,
        null
      );
    }
    if (!resp.ok) {
      throw new CertcryptNodeError(
        `getEmissionByCommitment failed: HTTP ${resp.status}`,
        resp.status,
        resp.text,
        resp.retryAfterMs
      );
    }
    return JSON.parse(resp.text) as EmissionHandleRecord;
  }

  /**
   * This integration's submissions the node gave up delivering (dead-lettered).
   *
   * A node keeps retrying an unreachable or unavailable server for as long as
   * it takes; what lands here is a refusal about the request or the node's own
   * credentials, which retrying unchanged cannot fix. Empty is the healthy
   * answer. Delivery metadata only — never the stored set.
   */
  async listDeadLetters(): Promise<DeadLetter[]> {
    const resp = await this.readWithRetry(
      `${this.baseUrl}/v1/outbox/dead`,
      () => ({}),
      "listDeadLetters"
    );
    if (!resp.ok) {
      throw new CertcryptNodeError(
        `listDeadLetters failed: HTTP ${resp.status}`,
        resp.status,
        resp.text,
        resp.retryAfterMs
      );
    }
    const body = JSON.parse(resp.text) as { dead?: Array<Record<string, unknown>> };
    return (body.dead ?? []).map((d) => ({
      requestId: String(d.request_id ?? ""),
      attempts: Number(d.attempts ?? 0),
      createdAtMs: Number(d.created_at_ms ?? 0),
      lastError: typeof d.last_error === "string" ? d.last_error : null,
    }));
  }

  /**
   * Put one dead-lettered submission back in the node's delivery queue, once
   * whatever refused it has been fixed. The node resends the SAME signed set
   * under the same `request_id` — nothing is re-signed, and the server
   * deduplicates. Throws 404 for an id this integration does not own.
   */
  async redriveDeadLetter(requestId: string): Promise<void> {
    const url = `${this.baseUrl}/v1/outbox/dead/${encodeURIComponent(requestId)}/redrive`;
    const resp = await this.fetchWithTimeout(url, {
      method: "POST",
      headers: this.authHeaders({ method: "POST", url }),
    });
    if (!resp.ok) {
      throw new CertcryptNodeError(
        `redriveDeadLetter failed: HTTP ${resp.status}`,
        resp.status,
        await resp.text(),
        retryAfterOf(resp).ms
      );
    }
  }

  /**
   * Fetch the current state of a node-local operation. Retried under the
   * transport-retry policy, like every read; a 404 (unknown id) is not.
   */
  async getOperation(operationId: string): Promise<OperationRecord> {
    return this.readOperation(operationId, true);
  }

  /** One operation read; `retry` false sends exactly one request (the wait loop
   *  owns its own retrying). */
  private async readOperation(operationId: string, retry: boolean): Promise<OperationRecord> {
    // The issuer's half of the read chain, bound to THIS operation id. The node
    // adds its own half and forwards both; the server verifies the pair. Binding the
    // resource is what stops a signature captured for one read from being
    // replayed against another operation.
    const url = `${this.baseUrl}/v1/operations/${encodeURIComponent(operationId)}`;
    let resp: { status: number; ok: boolean; text: string; retryAfterMs: number | null };
    if (retry) {
      resp = await this.readWithRetry(url, () => this.issuerReadHeaders(operationId), "getOperation");
    } else {
      const headers = this.authHeaders({ method: "GET", url }, this.issuerReadHeaders(operationId));
      const r = await this.fetchWithTimeout(url, { headers });
      resp = { status: r.status, ok: r.ok, text: await r.text(), retryAfterMs: retryAfterOf(r).ms };
    }
    if (resp.status === 404) {
      throw new CertcryptNodeError(
        `operation not found: ${operationId}`,
        404,
        null
      );
    }
    if (!resp.ok) {
      throw new CertcryptNodeError(
        `getOperation failed: HTTP ${resp.status}`,
        resp.status,
        resp.text,
        resp.retryAfterMs
      );
    }
    const body = JSON.parse(resp.text) as Record<string, unknown>;
    const record = normalizeOperationRecord(body);
    // A member the node delivered LATE (it answered `accepted_for_retry` at
    // submit) reaches `accepted` with an upstream id the issuer was never told.
    // The node's local record carries it; hand it over so the next read signs
    // the id the server routes on. Until then the node serves its local record,
    // so the cost is one poll, not a stuck operation.
    if (this.onUpstreamOperationId && record.state.state === "accepted") {
      const up = (record.state as { upstream_operation_id?: string }).upstream_operation_id;
      if (up) this.onUpstreamOperationId(operationId, up);
    }
    return record;
  }

  /**
   * List the emissions this integration has in flight — neither independently
   * verifiable yet nor terminally refused.
   *
   * `getOperation` requires an id, and an issuer that lost its handles lost the
   * ids with them: they travel only in the emission response. This endpoint lets
   * such an issuer enumerate its in-flight emissions instead of re-emitting,
   * which would open a second node operation for the same certificate — the
   * outcome the handle exists to prevent.
   *
   * Scope is this integration, resolved upstream from the key-set root proven by
   * the read chain, not from any credential of the node that relays it.
   *
   * The response carries no handle material. Each entry states what exists and
   * when to poll again; fetch the recoverable half one emission at a time.
   *
   * `truncated` means the page hit the server cap: narrow `since` rather than
   * treat the list as complete. A reconciler needs to distinguish a full listing
   * from a first page.
   */
  async listUnresolvedEmissions(
    since: string,
    limit?: number
  ): Promise<UnresolvedEmissions> {
    // The signed resource is the QUERY, not an id — a caller that lost its
    // handles has none. `since` is signed and sent as the SAME string: the node
    // relays it verbatim and the issuance service verifies both halves over identical bytes,
    // so reformatting it anywhere breaks the chain silently.
    const qs = new URLSearchParams({ since });
    if (limit !== undefined) qs.set("limit", String(limit));
    const resp = await this.readWithRetry(
      `${this.baseUrl}/v1/emissions/unresolved?${qs.toString()}`,
      () => this.issuerReadHeaders(`emissions:unresolved:${since}`),
      "listUnresolvedEmissions"
    );
    if (!resp.ok) {
      // No empty-list fallback on failure: a reconciler would read that as
      // "nothing pending" and act on it by re-emitting.
      throw new CertcryptNodeError(
        `listUnresolvedEmissions failed: HTTP ${resp.status}`,
        resp.status,
        resp.text,
        resp.retryAfterMs
      );
    }
    const body = JSON.parse(resp.text) as Record<string, unknown>;
    const raw = Array.isArray(body.emissions) ? body.emissions : [];
    return {
      emissions: raw.map((e) => {
        const r = e as Record<string, unknown>;
        return {
          operationId: String(r.operation_id ?? ""),
          status: String(r.status ?? ""),
          reasonCode: (r.reason_code as string | undefined) ?? null,
          updatedAt: String(r.updated_at ?? ""),
          targetCloseBy: (r.target_close_by as string | undefined) ?? null,
          expectedSettledBy: (r.expected_settled_by as string | undefined) ?? null,
          settledAt: (r.settled_at as string | undefined) ?? null,
          commitmentCount: Number(r.commitment_count ?? 0),
        };
      }),
      truncated: body.truncated === true,
    };
  }

  /**
   * Poll an operation until it reaches a terminal state (independent_ready,
   * rejected, expired, replay_detected, insufficient_capacity,
   * pre_evaluation_rejected, submission_failed), or throw.
   *
   * When the wait ends without one — attempts or `maxWaitMs` exhausted — this
   * throws `CertcryptNodeError` ("did not reach a terminal state"): the
   * operation is still progressing and the caller's handle stays valid, so poll
   * again later. A transient poll failure does not abort the wait; five
   * consecutive ones do, and a 404 (unknown id) surfaces at once. A node that
   * asks for a pause (503 or 429 with `Retry-After`) is waited out without
   * counting it as a failure. Each poll is one request, and time is read from
   * the client's clock.
   */
  async waitForOperation(
    operationId: string,
    opts: WaitOptions = {}
  ): Promise<OperationRecord> {
    // A caller that passes intervalMs/maxAttempts gets fixed-interval polling.
    // Only a caller that passes neither (or asks for it) gets the window-aware
    // scheduling.
    const explicitlyFixed = opts.intervalMs !== undefined || opts.maxAttempts !== undefined;
    const strategy = opts.strategy ?? (explicitlyFixed ? "fixed" : "auto");
    const intervalMs = opts.intervalMs ?? 1000;
    const backoffBaseMs = opts.backoffBaseMs ?? 1000;
    const backoffCapMs = opts.backoffCapMs ?? 30_000;
    // In fixed mode the attempt cap defaults to 60; in auto mode the wall
    // clock is the real bound and attempts are effectively unlimited.
    const maxAttempts = opts.maxAttempts ?? (strategy === "fixed" ? 60 : Number.MAX_SAFE_INTEGER);
    const maxWaitMs =
      opts.maxWaitMs ?? (strategy === "fixed" ? Number.POSITIVE_INFINITY : DEFAULT_MAX_WAIT_MS);

    const startedAt = this.now();
    let last: OperationRecord | null = null;
    let pollErrors = 0; // consecutive transient poll failures
    let lastWindow: SettlementWindowEstimate | undefined;
    // Sticky like `lastWindow`: a tick whose response omitted it should keep
    // reporting the last thing we actually knew rather than silently regressing.
    let lastSettlement: SettlementProgress | undefined;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        // One request per tick: this loop owns the retrying, so a blip is
        // counted here and a requested pause is bounded by `maxWaitMs`.
        last = await this.readOperation(operationId, false);
        pollErrors = 0;
        // Remember the last window the node reported: once the operation goes
        // terminal the field is gone, and a transient blip should not lose the
        // schedule we were waiting on.
        if (last.settlement_window) lastWindow = last.settlement_window;
        if (last.settlement_progress) lastSettlement = last.settlement_progress;
        if (isTerminal(last.state)) return last;
      } catch (e) {
        // A transient blip during polling (network, 5xx) must NOT abort the
        // wait — keep polling. A 404 is different (the op id is wrong); surface
        // it. Give up only after several consecutive transient failures.
        if (e instanceof CertcryptNodeError && e.status === 404) throw e;
        // The node asked for a pause (a restart): wait it out without counting
        // it as a failure — the same rule the submit path follows.
        if (e instanceof CertcryptNodeError && e.retryAfterMs !== null) {
          const asked = Math.min(Math.max(e.retryAfterMs, RETRY_AFTER_MIN_MS), RETRY_AFTER_MAX_MS);
          const left = maxWaitMs - (this.now() - startedAt);
          if (left <= 0) break;
          await this.sleepMs(Math.min(asked, left));
          continue;
        }
        pollErrors += 1;
        if (pollErrors >= 5) throw e;
      }

      const now = this.now();
      const elapsedMs = now - startedAt;
      const { delayMs, overdue } =
        strategy === "fixed"
          ? { delayMs: intervalMs, overdue: false }
          : nextPollDelayMs({
              attempt: attempt + 1,
              now,
              window: lastWindow,
              backoffBaseMs,
              backoffCapMs,
              random: this.random,
            });

      // Stop at the wall-clock bound rather than sleeping past it.
      const remaining = maxWaitMs - elapsedMs;
      if (remaining <= 0) break;
      const sleepMs = Math.min(delayMs, remaining);

      const progress: Omit<WaitProgress, "message"> = {
        attempt: attempt + 1,
        nodeState: last?.state.state ?? "unknown",
        nextCheckInMs: sleepMs,
        elapsedMs,
        ...(lastWindow ? { window: lastWindow } : {}),
        ...(lastSettlement ? { settlement: lastSettlement } : {}),
        overdue,
      };
      const message = describeWait(progress);

      if (opts.onProgress) {
        try {
          opts.onProgress({ ...progress, message });
        } catch {
          // A reporting callback must never break the wait.
        }
      } else if (sleepMs >= QUIET_WAIT_WARN_MS || overdue) {
        // NOBODY is listening and we are about to sleep for a long time (or the
        // operation is already late). An unannounced multi-minute sleep is
        // indistinguishable from a hang, and the issuer would reasonably kill the
        // process. Say it once per tick on the console; a caller that wants
        // structured reporting passes onProgress and this never fires.
        // eslint-disable-next-line no-console
        console.info(`[certcrypt] operation ${operationId}: ${message}`);
      }

      await this.sleepMs(sleepMs);
    }

    const waited = this.now() - startedAt;
    throw new CertcryptNodeError(
      `operation ${operationId} did not reach a terminal state after ${Math.round(waited / 1000)}s` +
        (last ? ` (last state: ${last.state.state})` : "") +
        (lastWindow?.expected_settled_by
          ? `; operator expected window ${lastWindow.window_profile} to be settled by ` +
            `${lastWindow.expected_settled_by}` +
            (isSettlementOverdue(lastWindow, this.now())
              ? ` — it is OVERDUE: settlement is past the operator's expected instant`
              : "")
          : lastWindow?.target_close_by
            ? `; node expected window ${lastWindow.window_profile} to close by ${lastWindow.target_close_by}` +
              ` — it is OVERDUE: settlement is taking longer than the window allows`
            : ""),
      null,
      null
    );
  }

  /**
   * Assemble the full `verification-package/1` for one operation so the issuer
   * can verify its OWN Proof of Independence OFFLINE (dogfooding). No new node
   * surface: the node is a non-custodian and never returns base_certificate /
   * capacity_evidence / the commitment inclusion proof. This gathers:
   *   - base_certificate + capacity_evidence — client-held (passed in);
   *   - independence_proof + settlement_material — from GET /v1/operations/{id}
   *     once independent_ready (base64 → parsed JSON);
   *   - commitment_inclusion_proof — DERIVED locally from the proof's
   *     `consumed_commitment_ids` + this commitment's index (same Merkle
   *     primitive the verifier recomputes).
   *
   * Throws if the operation is not `independent_ready`, if the server artifacts are
   * missing, or if the proof lacks `consumed_commitment_ids`.
   */
  async buildVerificationPackage(
    operationId: string,
    opts: BuildPackageOptions
  ): Promise<VerificationPackage> {
    const rec = await this.waitForOperation(operationId, opts.wait);
    if (rec.state.state !== "independent_ready") {
      throw new CertcryptNodeError(
        `operation ${operationId} is not independent_ready (state: ${rec.state.state}) — no proof to package`,
        null,
        null
      );
    }
    if (!rec.independence_proof || !rec.settlement_material) {
      throw new CertcryptNodeError(
        `operation ${operationId} reached independent_ready but the node returned no proof/settlement material`,
        null,
        null
      );
    }

    const independenceProof = JSON.parse(
      Buffer.from(rec.independence_proof, "base64").toString("utf8")
    ) as Record<string, unknown>;
    const settlementMaterial = JSON.parse(
      Buffer.from(rec.settlement_material, "base64").toString("utf8")
    ) as unknown;

    const consumedIds = independenceProof.consumed_commitment_ids;
    if (!Array.isArray(consumedIds) || consumedIds.length === 0) {
      throw new CertcryptNodeError(
        `independence_proof for ${operationId} has no consumed_commitment_ids — cannot derive the inclusion proof`,
        null,
        null
      );
    }
    const commitmentInclusionProof = buildCommitmentInclusionProof(
      consumedIds as string[],
      opts.commitmentIndex
    );

    return {
      base_certificate: opts.baseCertificate,
      independence_proof: independenceProof,
      verification_context: opts.verificationContext,
      capacity_evidence: opts.capacityEvidence,
      commitment_inclusion_proof: commitmentInclusionProof,
      settlement_material: settlementMaterial,
    };
  }

  /**
   * Assemble a `verification_package` from artifacts already in hand.
   *
   * Same shaping as `buildVerificationPackage`, without the polling: the caller
   * recovered the proof and the settlement material some other way — by the
   * capacity-evidence digest, typically, when the node that emitted no longer has
   * the operation.
   *
   * The package is identical either way. Nothing here is node-supplied: the
   * inclusion proof is derived from the proof's own `consumed_commitment_ids`, and
   * the rest comes from the handle the issuer kept.
   */
  assembleVerificationPackageFromProof(opts: {
    independenceProofB64: string;
    settlementMaterialB64: string;
    baseCertificate: unknown;
    capacityEvidence: unknown;
    verificationContext: { rules_version: string; system_id: string };
    commitmentIndex: number;
  }): VerificationPackage {
    const independenceProof = JSON.parse(
      Buffer.from(opts.independenceProofB64, "base64").toString("utf8")
    ) as Record<string, unknown>;
    const settlementMaterial = JSON.parse(
      Buffer.from(opts.settlementMaterialB64, "base64").toString("utf8")
    ) as unknown;

    const consumedIds = independenceProof.consumed_commitment_ids;
    if (!Array.isArray(consumedIds) || consumedIds.length === 0) {
      throw new CertcryptNodeError(
        "independence_proof has no consumed_commitment_ids — cannot derive the inclusion proof",
        null,
        null
      );
    }

    return {
      base_certificate: opts.baseCertificate,
      independence_proof: independenceProof,
      verification_context: opts.verificationContext,
      capacity_evidence: opts.capacityEvidence,
      commitment_inclusion_proof: buildCommitmentInclusionProof(
        consumedIds as string[],
        opts.commitmentIndex
      ),
      settlement_material: settlementMaterial,
    };
  }
}
