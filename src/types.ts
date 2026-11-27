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
 * Wire types for the node's HTTP surface — this SDK's only network peer.
 *
 * The issuer (this SDK) projects and Level-3 signs a `capacity.evidence/1` with a
 * per-operation leaf of its operation-key tree and submits it. See
 * `artifacts/capacity-evidence.ts` for the byte contract.
 */

/**
 * A closed `submission-set/1` artifact on the wire, as an opaque JSON object.
 * The node assembles it from the commitments you submit.
 */
export type SubmissionSetWire = Record<string, unknown>;

/**
 * One commitment as submitted. The SDK signs only the holder's
 * `capacity_evidence` — the one step no one else can perform — and 1..N of these
 * are assembled into a `submission-set/1`.
 *
 * `operative` carries the integration's fixed `(holder_id, pool_id)`, issued at
 * onboarding and configured once in `NodeClientOptions.pool_id`: carried through,
 * never freely declared per call. Safe in clear because it is not accepted on
 * assertion — the server re-derives the holder/pool pseudonyms from it under the
 * evidence's own `operation_salt` and rejects the member unless they equal the
 * signed ones (submission-set/1 §7.2).
 *
 * These two fields are the whole member (submission-set/1 §7.1): the member
 * carries what the protocol needs and can verify, and nothing chosen freely by
 * the issuer. Results correlate by `commitment_index`.
 */
export interface LooseCommitment {
  /** The holder-signed zero-data commitment (capacity.evidence/1, projected). */
  capacity_evidence: unknown;
  /** Routing context for this certificate. Never reaches the verifier. */
  operative: { holder_id: string; pool_id: string };
}

/** Request body for `POST /v1/issue`. */
export interface IssueRequest {
  /**
   * Optional idempotency key (26-char ULID). If omitted, the node generates
   * one. Reusing it makes the upstream submission idempotent.
   */
  request_id?: string;
  /**
   * The loose commitments to wrap into one submission-set (1..N, same issuer +
   * authorization). The node assembles the set; the SDK never builds it.
   */
  commitments: LooseCommitment[];
  /**
   * Issuer-elected settlement-window preference: how soon the emission's window
   * closes, and therefore how soon it can reach `Independent`. Omit to accept the
   * default. Operational only — it is never part of the submission_set, the proof,
   * or anything a verifier evaluates.
   */
  settlement_preferences?: {
    /**
     * Which settlement window to close this emission's aggregate under — e.g.
     * `"close_3min"` (the default profile) or `"close_6h"`.
     *
     * It is NEVER a trust tier or a proof level. A certificate settled under a
     * slow window is evaluated by the same public rules and reaches
     * `Independent` on the same conditions as one settled under a fast window.
     */
    window_profile: string;
    /**
     * What to do when the elected `window_profile` cannot be honored.
     * `"slower_allowed"` permits degrading to a slower profile; `"reject"`
     * prefers to fail. A window is never degraded to a FASTER one: a fallback
     * may only move toward a slower profile.
     */
    fallback_policy: "reject" | "slower_allowed";
  };
}

/**
 * Node-local operation state, discriminated by `state`. Mirrors the node's
 * `OperationState`.
 */
export type OperationState =
  // Per-member outcomes:
  | { state: "accepted"; upstream_operation_id: string }
  | { state: "rejected"; reason_code: string; message: string }
  | { state: "replay_detected"; message: string }
  | { state: "insufficient_capacity" }
  // Whole-request outcomes (no per-member evaluation reached):
  | { state: "pre_evaluation_rejected"; reason_code: string; message: string }
  // Transport failed, but the node has taken durable custody of the set and will
  // deliver it. Non-terminal: poll GET /v1/operations/{id} for the outcome rather
  // than re-submitting. Returned with HTTP 202.
  | { state: "accepted_for_retry"; error: string }
  // The submission did not get through and the node is NOT holding it for retry.
  // With `upstream_status` (HTTP 422 from the node): the CERTCRYPT service
  // definitively refused the request with that HTTP status, so resending the same
  // bytes cannot change the answer — fix the cause first. Without it: the service
  // answered in a way the node could not use, or the node could not record the
  // outcome.
  | { state: "submission_failed"; error: string; upstream_status?: number }
  // Later async finalization (polled via GET /v1/operations/{id}):
  | { state: "processing"; upstream_operation_id: string }
  | { state: "independent_ready"; upstream_operation_id: string }
  // Terminal after processing (submission-set/1 §11.1): the accepted member can
  // no longer reach Independent and nothing was consumed. Not a rejection — the
  // member was valid; its authorization ran out. The certificate stays Issued;
  // re-submit it under a fresh authorization.
  | { state: "expired"; reason_code: string; message: string };

/** One per-member result in an IssueResponse (per `submission-set/1`). */
export interface MemberResult {
  /** Node-local operation id for this member (key for GET /v1/operations/{id}). */
  operation_id: string;
  /** Position of this member in the submitted set — what maps this result back
   *  to its input. An issuer keeping its own label for a certificate associates
   *  it with this position locally. */
  commitment_index: number;
  state: OperationState;
}

/**
 * Response of `POST /v1/issue`. The node returns EITHER a per-member shape
 * (`results[]` populated, `state` absent — the normal path) OR a whole-request
 * shape (`results` empty, `state` set — a pre-evaluation rejection or transport
 * failure). Mutually exclusive.
 */
export interface IssueResponse {
  request_id: string;
  /** The server's submission-set identity, when member evaluation was reached. */
  submission_set_id?: string;
  /** One result per submitted member. Empty on a whole-request outcome. */
  results: MemberResult[];
  /** Whole-request outcome, set ONLY when no per-member evaluation happened. */
  state?: OperationState;
}

/**
 * Response of the issuance service's `by-commitment` lookup, relayed verbatim by the node.
 *
 * Deliberately smaller than `OperationRecord`: this lookup recovers a handle, not
 * the scheduling view. What it must carry is what the issuer does NOT already
 * hold — the proof and the settlement material. Everything else the verification
 * package needs is in the handle the issuer kept.
 */
export interface EmissionHandleRecord {
  operation_id: string;
  status: string;
  reason_code?: string;
  /** base64 of the canonical `independence.proof/1`; only on `independent_ready`. */
  independence_proof?: string;
  /** base64 of the leaf's `settlement-material/1`; only on `independent_ready`. */
  settlement_material?: string;
  window_status?: string;
  window_settled_at?: string;
}

/** Response of `GET /v1/operations/{id}`.
 *
 * The node returns one of TWO shapes on this route:
 *  - a local record `{operation_id, request_id, state}` (not yet reconciled), or
 *  - the server's authoritative body forwarded verbatim when a member reconciles to
 *    a terminal outcome: `{operation_id, status, independence_proof?,
 *    settlement_material?}` — `status` (string) instead of `state`, no
 *    `request_id`, and (only when `independent_ready`) the two server-produced proof
 *    artifacts, base64-encoded.
 *
 * `getOperation` normalizes both into this single shape: `state` is always
 * populated (derived from `status` when the server body is forwarded), and the two
 * proof fields are surfaced when present so a client can assemble the
 * `verification_package`. `request_id` is optional (absent on the server body). */
export interface OperationRecord {
  operation_id: string;
  request_id?: string;
  state: OperationState;
  /** base64 of the canonical `independence.proof/1` bytes — present only when
   *  the operation is `independent_ready` (server-produced artifact). */
  independence_proof?: string;
  /** base64 of the canonical SettlementMaterial JSON — present only when
   *  `independent_ready` (server-produced artifact). */
  settlement_material?: string;
  /** The settlement window this operation is assigned to, while it is being settled.
   *  Lets a poller wait UNTIL the window instead of spinning. See
   *  {@link SettlementWindowEstimate}. */
  settlement_window?: SettlementWindowEstimate;
  /** How far the settlement backing this operation has come, while it is in flight.
   *  Distinguishes "queued behind a window" from "on chain, waiting for the
   *  substrate's irreversibility". See {@link SettlementProgress}. */
  settlement_progress?: SettlementProgress;
}

/**
 * Advisory progress indicator for an in-flight settlement.
 *
 * NOT A VERDICT, and never a substitute for the artifacts. `state` remains the
 * authority; this only says how far along the wait is. In particular
 * `finality_pending` is NOT verifiable evidence: the settlement profile refuses every
 * provisional, head-only or soft-confirmed action, so an operation only carries a
 * temporal claim once its artifacts are served with `independent_ready`.
 *
 * Deliberately opaque about the substrate: a coarse phase and a normalized fraction,
 * never blocks, ledgers, finality heights or the chain's finality model. Render a bar from
 * it; do not infer how the chain works, and do not gate anything on it.
 */
export interface SettlementProgress {
  /**
   * `queued` — assigned to a window, nothing on chain yet.
   * `finality_pending` — settled on chain, waiting for irreversibility.
   * `final` — irreversible.
   *
   * Treated as an open string on purpose: a future substrate may add a phase, and an
   * SDK that switches exhaustively on it would break. Branch on the ones you know and
   * fall through on the rest.
   */
  phase: string;
  /** Progress toward irreversibility as a fraction × 1e6 (743000 = 74.3%). Absent
   *  before broadcast, and where the substrate has immediate finality. */
  progress_ppm?: number;
  /** When the operator last sampled the chain for that fraction (RFC3339). An
   *  observation timestamp — NOT the settlement's temporal claim, which comes only
   *  from the irreversible block time inside the settlement material. */
  observed_at?: string;
}

/**
 * The node's estimate of WHEN this operation's settlement window closes, so a
 * poller can schedule its next check instead of guessing.
 *
 * OPERATIONAL ONLY. It is never part of the submission_set, the proof, or
 * anything a verifier evaluates — the same character as the request's
 * `settlement_preferences`. It describes the NODE's schedule, not the issuer:
 * knowing that a window runs late says nothing about who issued into it.
 *
 * ZERO-DATA BOUNDARY — deliberately absent, and must stay absent: this carries
 * NO amount and NO capacity figure. In the clear on every response, an
 * operation's cost would make an issuer's operations correlatable over time —
 * and once a value travels in a response it is copied into logs, whoever it was
 * meant for. The consumed quantity is carried only in the `settlement_material`
 * that the `independence_proof` binds.
 */
export interface SettlementWindowEstimate {
  /** The frozen issuer-elected window profile, as an opaque versioned label.
   *  Log it, show it in support, but never branch on it: schedule on
   *  `target_close_by`. */
  window_profile: string;
  /** The profile version the election was frozen against. */
  window_profile_version: string;
  /** RFC 3339 instant the window is expected to CLOSE. Absent when the node has
   *  frozen a profile but cannot yet name a target. Note this is the window's
   *  close target, NOT the moment the package is ready: chain finality adds more
   *  after it. Treat it as "not before", never as a deadline. */
  target_close_by?: string;
  /** RFC 3339 instant by which the operator expects this window's settlement to be
   *  anchored and final, so that a read can return a terminal state. Never earlier
   *  than `target_close_by`; present exactly when it is. The SDK schedules its next
   *  check on it and reports the operation `overdue` only once it has passed.
   *  An operational ESTIMATE from the operator: not a promise of when the
   *  operation becomes Independent, and not proof material. */
  expected_settled_by?: string;
}

/** One in-flight emission for this integration, as `listUnresolvedEmissions`
 *  returns it.
 *
 *  Not handle material: enough to decide what to fetch and when to poll again,
 *  and cheap enough for a routine pending-work check. The recoverable half of a
 *  handle is fetched one emission at a time.
 *
 *  `commitmentIndex` is absent here on purpose — it is not knowable while an
 *  emission is unresolved (it lives in the Proof of Independence, which does not
 *  exist until the settlement window closes). */
export interface UnresolvedEmission {
  /** The id the issuer knows this emission by — the same value its lost handle
   *  carried as `operation_id`. */
  operationId: string;
  /** Public ontology only: the node reports public states, never internal ones. */
  status: string;
  reasonCode: string | null;
  /** RFC 3339. */
  updatedAt: string;
  /** RFC 3339 close TARGET of the settlement window, when one was assigned.
   *  Schedule the next poll on it; treat it as "not before", never a deadline. */
  targetCloseBy: string | null;
  /** RFC 3339 instant by which the operator expects the settlement to be anchored
   *  and final, when a window was assigned (never earlier than `targetCloseBy`).
   *  An operational estimate: the best moment for the next poll. */
  expectedSettledBy: string | null;
  /** RFC 3339 effective settle time, when already settled. */
  settledAt: string | null;
  /** How many handles this emission yields for this integration. */
  commitmentCount: number;
}

/** The answer to "what do I still have open?".
 *
 *  `truncated` is true when the page hit the server-side cap. It MUST NOT be
 *  ignored: a reconciler that reads a truncated page as complete concludes there
 *  is nothing left to finish, and the recovery it skips becomes a re-emission. */
export interface UnresolvedEmissions {
  emissions: UnresolvedEmission[];
  truncated: boolean;
}
