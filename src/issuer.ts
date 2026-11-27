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
 * Certcrypt — high-level issuer client.
 *
 * Wraps the low-level CertcryptNodeClient and hides all the plumbing an app
 * would otherwise reimplement: keyset derivation, activation (TOFU),
 * caching the minted Level-1 binding, per-operation salt, and — in the
 * unlinkable mode — never-reused leaf bookkeeping. An integrating app does:
 *
 *   const certcrypt = new Certcrypt({ nodeBaseUrl, keysetSeed,
 *                                        integrationKey, mode: "stable",
 *                                        rulesVersion, systemRootFingerprint, systemId });
 *
 * THE SAME CODE ON EVERY START — there is no "first run" branch. `keysetSeed` and
 * `integrationKey` are two halves of one boot credential: provision both from config
 * (env / secret manager) and keep them. Nothing else has to be persisted for the
 * issuer to survive a restart.
 *
 * Why that works: the keyset root is re-derived from the seed, so re-presenting the
 * same `integrationKey` is an idempotent replay the server answers with the same binding.
 * The key is "one-time" only in that its FIRST use permanently TOFU-binds it to this
 * seed's root; presenting it with a DIFFERENT root is refused (409). That protects
 * against hijack, not against your own restart. (One caveat before that first use: an
 * UNREDEEMED key expires. The window is stated in your onboarding materials — activate
 * promptly, or request a new key.)
 *
 * Optional: pass a `bindingStore` to cache the binding and skip the activation
 * round-trip on start. It is a CACHE — omitting it is fully supported and costs one
 * request per start.
 *   const res = await certcrypt.issue({
 *     subjects: [{ profile: "subject.text/1", material: myTextBytes }],
 *   });
 *
 * `issue()` certifies the MATERIAL (subject.text/1, subject.binary/1, …): it mints
 * a signed base_certificate whose commitment is derived from the material and
 * submits it toward Independent, so a third party can verify the binding OFFLINE.
 * A certificate commits to an ORDERED SET of subjects: pass one for a single-subject
 * cert, or several (dual-cert etc.) — one leaf/signature binds the whole set. The
 * order is significant; consumers may rely on subjects[0] being the primary face.
 * The issuer supplies only the material — the SDK derives the signing key from the
 * seed and does the rest. Persist `res.handle`; call `resolveEmission(handle)` to
 * get the verification-package once it settles.
 *
 * TWO KEY MODES:
 *  - "stable" (DEFAULT): a tiny key set (size 1), the key is REUSED. No counter,
 *    no exhaustion, no leaf store. The issuer's certs
 *    are linkable to each other, and therefore RECOGNIZABLE as its own — usually
 *    the point for an institutional or server issuer. Leaf-reuse is a PRIVACY
 *    choice, not a protocol mandate: reusing a leaf leaves the cert VALID, only
 *    correlatable.
 *  - "unlinkable" (OPT-IN): a large key set + a DISTINCT leaf per cert + no reuse,
 *    so the capacity layer never repeats a key. Every certificate is still
 *    signed with the same issuer key, so a party holding two of them can tell they
 *    share an issuer; what stays unlinkable is the protocol surface. Needs a `leafStore` (persistent
 *    nextLeaf()). The SDK enforces the no-reuse because a verifier cannot detect a
 *    repeat: nothing in the artifacts reveals that a leaf was used twice, so the
 *    property is lost silently if the issuer does not hold the line.
 */
import { randomBytes } from "node:crypto";
import {
  CertcryptNodeClient,
  CertcryptNodeError,
  isSettlementOverdue,
  isTerminalState,
  issuerAuthMessage,
  type IssuerAuthRequest,
  type NodeClientOptions,
  type RetryOptions,
  type VerificationPackage,
  type WaitOptions,
} from "./client.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";
import {
  assertSubmissionSetWithinBound,
  evidenceDigestHex,
} from "./artifacts/capacity-evidence.js";
import type { SignedLevel1Binding } from "./artifacts/capacity-evidence.js";
import {
  deriveIssuerKey,
  generateNonceHex,
  computeExpiresAt,
  resolveCollectionSubjects,
  type IssuerKey,
  type ResolvedCollection,
  type SubjectInput,
} from "./artifacts/base-certificate.js";
import { SUBJECT_COLLECTION } from "./crypto/canonical-subject.js";
import { strictJsonParse } from "./crypto/strict-json.js";
import type {
  IssueResponse,
  LooseCommitment,
  SettlementWindowEstimate,
  UnresolvedEmissions,
} from "./types.js";

/**
 * Σ of the certificate's per-subject effective units, as the capacity evidence
 * declares it (`submission-set/1`). Each subject contributes:
 *   - a `subject.collection/1` → its `declared_cardinality` (a batch of N items), and
 *   - any other subject          → 1.
 * So a 3-subject certificate declares "3", a single-subject one "1", and one with a
 * 500-item collection subject declares 500 (plus its siblings). Returned as the
 * canonical decimal string the evidence uses.
 *
 * The server re-derives the same sum from the minted base_certificate and rejects a
 * mismatch fail-closed, so the declaration cannot understate what the certificate
 * actually carries.
 */
function sumEffectiveUnits(subjects: SubjectInput[]): string {
  let total = 0n;
  for (const s of subjects) {
    if (s.profile === SUBJECT_COLLECTION) {
      // Declared by leaves: the cardinality IS the leaf count, and no descriptor
      // exists yet (its root needs the anchor nonce).
      if (s.leaves) {
        const n = BigInt(s.leaves.length);
        total += n > 0n ? n : 1n;
        continue;
      }
      // Otherwise the declared_cardinality lives in its JSON material.
      try {
        const obj = strictJsonParse(Buffer.from(s.material!).toString("utf8")) as
          { declared_cardinality?: unknown } | null;
        const dc = BigInt(String(obj?.declared_cardinality ?? "0"));
        total += dc > 0n ? dc : 1n;
      } catch {
        total += 1n; // malformed collection: count as 1 (the node re-derives + rejects).
      }
    } else {
      total += 1n;
    }
  }
  return total.toString();
}

/** Persistent, monotone leaf allocator for the unlinkable mode. Each call MUST
 *  return a fresh index never handed out before (survives restarts). */
export interface LeafStore {
  nextLeaf(): Promise<number>;
}

/** A trivial in-memory leaf store — NOT persistent. Only for tests / single-run
 *  scripts; a real unlinkable deployment must supply a durable store: this one
 *  restarts at zero, which silently reuses every leaf it already handed out. The
 *  SDK never picks it for you — `mode: "unlinkable"` without a `leafStore` is
 *  refused at construction. */
export class InMemoryLeafStore implements LeafStore {
  private cursor = 0;
  async nextLeaf(): Promise<number> {
    return this.cursor++;
  }
}

/**
 * Optional persistence for the Level-1 binding — a CACHE that saves the activation
 * round-trip on start, never a requirement for correctness. With only `integrationKey`
 * + `keysetSeed` the SDK re-activates by itself (the key replays idempotently against
 * the same root), so an empty or failing store degrades to "one extra request".
 *
 * `save()` receives `holderId`/`poolId` alongside the binding and `load()` MUST return
 * them: both are LEARNED from activation and authoritative for emission (emission is
 * attributed to `holder_id`). A store that persisted only the binding would
 * leave `holderId` unresolved and `issue()` would throw — which is exactly the trap of
 * supplying a bare `signedLevel1` by hand.
 *
 * No default implementation is provided on purpose: the binding carries `holder_id` and
 * `pool_id`, so where it lives is a deployment decision (DB, secret manager, file) the
 * SDK should not make for the integrator.
 */
export interface BindingStore {
  load(): Promise<BindingStoreEntry | null>;
  save(entry: BindingStoreEntry): Promise<void>;
}

/** What a BindingStore round-trips: the binding plus the two identifiers the
 *  activation bound to it. All three are public (no secret) — safe to persist. */
export interface BindingStoreEntry {
  binding: SignedLevel1Binding;
  holderId: string;
  poolId: string;
}

export type IssuerMode = "stable" | "unlinkable";

export interface CertcryptOptions {
  /** Node base URL (the SDK talks only to the node). */
  nodeBaseUrl: string;
  /** 32-byte master seed (64-hex or Uint8Array). Secret; never leaves the app. */
  keysetSeed: string | Uint8Array;
  /** The integration's pool_id (from onboarding). Optional if learned from activate. */
  poolId?: string;
  /** Stable holder id for this integration. Normally LEARNED from activation (the
   *  issuance service binds and returns it), so it is optional. Set it only when supplying a
   *  pre-obtained `signedLevel1` that skips activation — it MUST then equal the
   *  holder the integration was activated under, or the emission is not accounted
   *  for against this integration. */
  holderId?: string;
  /** Published system context (from onboarding config). */
  rulesVersion: string;
  systemRootFingerprint: string;
  /** The system domain id (e.g. "certcrypt"), stamped into the verifiable
   *  certificate's anchor. From onboarding config. */
  systemId?: string;
  /** The capacity-commitment TTL (seconds) from the ACTIVE rules-domain registry
   *  (e.g. 86400 for a one-day TTL). The verifier requires
   *  expires_at == issued_at + this TTL, so issue() derives expires_at from it
   *  rather than a caller value. Omitting it uses the published TTL of the
   *  configured rules domain; a domain registered with `registerRulesDomain` has
   *  no published TTL, so it must be set there or issuance fails. */
  commitmentTtlSeconds?: number;
  /** The integration's activation key (from onboarding). KEEP IT: supply it
   *  on EVERY start, exactly like `keysetSeed` — it is not consumed by use.
   *
   *  It is "one-time" in one specific sense: the FIRST activation TOFU-binds it to
   *  this `keysetSeed`'s root, permanently. Re-presenting it with the SAME root is
   *  an idempotent replay the server answers with the same binding
   *  (`already_consumed_same_root`), which is what makes a cold restart work with no
   *  persisted state. Presenting it with a DIFFERENT root is refused (409) — that is
   *  the hijack the TOFU closes, not your restart.
   *
   *  Caveat before the first activation: an UNREDEEMED key expires. The window is
   *  stated in your onboarding materials — activate promptly, or request a new key.
   *  Once redeemed it replays indefinitely — the consumed branch is evaluated before
   *  the expiry one, by design. */
  integrationKey?: string;
  /** A pre-obtained Level-1 binding. An OPTIMIZATION that skips the activation
   *  round-trip on start — NOT a requirement, and NOT a substitute for keeping
   *  `integrationKey` (with the key alone the SDK re-activates by itself).
   *
   *  Supplying this WITHOUT `integrationKey` means activation never runs, so the
   *  canonical `holderId` is never learned — set `holderId` explicitly too, or
   *  `issue()` will throw. Prefer a `bindingStore`, which caches all three together. */
  signedLevel1?: SignedLevel1Binding;
  /** Optional cache for the Level-1 binding, so a restart skips the activation
   *  round-trip. A CACHE, not a source of truth: on a miss (or a load error) the SDK
   *  re-activates from `integrationKey`, so a cold store is never fatal. Omit it and
   *  the SDK simply re-activates on every start. */
  bindingStore?: BindingStore;
  /** Key mode. Default "stable". */
  mode?: IssuerMode;
  /** Issuer key id stamped into the base_certificate signer block. Default
   *  `"issuer:" + keysetRoot[0:32]`. A label only: the signing key depends on
   *  `keysetSeed` alone, so changing the id never changes the key (conformance
   *  family `issuer-key-derivation`). Not a secret. */
  issuerKeyId?: string;
  /** A pre-provisioned composite issuer key (e.g. KMS-backed) for verifiable
   *  issuance. OPTIONAL: when omitted, `issue()` derives one DETERMINISTICALLY
   *  from `keysetSeed` (domain-separated) so the issuer provisions only the seed.
   *  Supply this only to harden production custody. */
  issuerKey?: IssuerKey;
  /** Tree size. Default: 1 for stable, 4096 for unlinkable. */
  treeSize?: number;
  /** Leaf allocator for the unlinkable mode. Required when mode="unlinkable":
   *  construction throws without one, because a default that restarts at zero
   *  would silently reuse leaves. */
  leafStore?: LeafStore;
  /** End of the minted authorization's validity (RFC3339 seconds). Default
   *  `FAR_FUTURE`. Only used when activating. Its start is not the issuer's to
   *  choose: the issuance service fixes it (the activation instant, never before
   *  the Level-1 key that signs it) and the SDK reads it from the answer. */
  validUntil?: string;
  /** Optional custom fetch (tests). */
  fetch?: typeof fetch;
  /**
   * How long a submit or a read keeps retrying while the node is unreachable or
   * asks for a pause (a restart, an outbox it could not write). Default: 120 s,
   * no attempt limit, backoff base 200 ms and cap 30 s. Raise `maxElapsedMs` if
   * your process can wait longer for a node restart; lower it if a caller
   * upstream needs an answer sooner (a mail filter that would rather defer the
   * message, for instance).
   */
  retry?: RetryOptions;
}

/** Issuer-elected settlement-window preference: how soon this emission's window
 *  closes, and therefore how soon the certificate can reach `Independent`.
 *  Optional — omit it to accept the default.
 *
 *  Operational only: the window profile is never part of the submission_set, the
 *  proof, or anything a verifier evaluates. Choosing a faster window changes when
 *  a certificate becomes independently verifiable, never whether it is valid. */
export interface SettlementPreferences {
  /** Identifier of a published window profile. The available profiles and the
   *  current default are documented at https://docs.certcrypt.com — they are
   *  resolved at submission rather than pinned here, so a profile added or
   *  retired later needs no SDK release.
   *
   *  Validated on submit: an unknown or inactive profile is rejected fail-closed
   *  unless `fallbackPolicy: "slower_allowed"`. */
  windowProfile: string;
  /** `reject` (default, fail-closed) | `slower_allowed` (record an explicit
   *  downgrade to a slower profile if the requested one cannot be accepted). */
  fallbackPolicy?: "reject" | "slower_allowed";
}

/**
 * Input to `issue()` — the ONE issuance surface. The issuer supplies only the
 * MATERIAL and its subject profile; the SDK does everything else (derives the
 * signing key from the seed, canonicalizes the subject byte-identically to the
 * verifier, mints a SIGNED base_certificate whose commitment is derived FROM the
 * material, and submits it toward Independent). This is the primary issuance surface:
 *
 *   await certcrypt.issue({ subjects: [{ profile: "subject.text/1", material }] });
 *
 * There is no opaque-digest mode: `issue()` always commits to real material, so a
 * third party can bind the Proof of Independence to THIS exact content. (To
 * certify a non-document fact, model it as a subject — e.g. subject.ai-decision/1
 * over a canonical JSON — rather than passing a bare digest.)
 */
export interface IssueInput {
  /** The ORDERED set of subjects the certificate commits to, each a material +
   *  its subject profile (subject.text/1, subject.binary/1, subject.email/1,
   *  subject.collection/1, subject.ai-decision/1). Pass ONE for a single-subject
   *  certificate, or SEVERAL for a multi-subject one (dual-cert: assertion + PDF,
   *  …) — a single leaf/signature binds the whole set. MUST be non-empty; the
   *  order is significant (consumers may rely on subjects[0] as the primary face).
   *  The SDK canonicalizes each per profile and commits to it in the base_certificate. */
  subjects: SubjectInput[];
  /** Declared effective units. Default: the sum over `subjects` (1 per subject,
   *  a collection's `declared_cardinality` for a collection), which the node
   *  re-derives and must match. */
  declaredEffectiveUnits?: string;
  /**
   * Consumed quantity (default `"0"`). **Leave it unset.**
   *
   * A caller cannot know this value: it is resolved server-side and is not final
   * until the operation completes. Nothing reads what you put here. The quantity
   * actually consumed comes back in the `settlement_material` that the
   * `independence_proof` binds — that is the authoritative figure, and the only one
   * worth recording.
   */
  consumedQuantity?: string;
  /** issued_at / expires_at (RFC3339 seconds). Default issued=now, expires=issued_at
   *  plus the rules domain's commitment TTL, which a verifier requires exactly. */
  issuedAt?: string;
  expiresAt?: string;
  /** Issuer-elected settlement window (see `SettlementPreferences`). Omit for the
   *  default. */
  settlementPreferences?: SettlementPreferences;
}

/**
 * One certificate SIGNED but not yet sent — what `prepare()` returns and
 * `submit()` consumes.
 *
 * N unrelated certificates sent as N requests carry the per-submission overhead N
 * times, while the same N prepared and submitted together carry it ONCE — the
 * reason this surface exists.
 *
 * TREAT IT AS SPENT THE MOMENT YOU HOLD IT. `prepare()` signs, and signing is what
 * consumes the leaf and the operation salt; sending does not. In "unlinkable" mode a
 * prepared commitment that is never submitted leaves its leaf spent for good: the
 * leaf allocator is monotone by design (`LeafStore` has no `release()`), because
 * recycling a leaf would reintroduce the reuse a verifier cannot detect. Losing a
 * leaf costs one slot in a large key set; reusing one silently destroys the
 * unlinkability the mode exists to provide. In "stable" mode leaf 0 is reused on
 * purpose, so nothing is lost.
 *
 * Serializable: persist it (JSON) if the submit happens in another process. What you
 * must NOT do is re-`prepare()` the same certificate to retry a failed send — that
 * signs a second commitment for the same material. Re-`submit()` the one you hold.
 */
export interface PreparedCommitment {
  /** The signed loose commitment, exactly as it will travel on the wire. */
  commitment: LooseCommitment;
  /** The signed base_certificate. Needed to build the handle after the submit and
   *  to verify the emission offline against the original material. Typed `unknown`
   *  to match `EmissionHandle` — it travels as an opaque signed blob. */
  baseCertificate: unknown;
  /** Resolved collection subjects (descriptor + leaf hashes, in leaf order). They
   *  also travel signed inside the certificate's collection descriptor and can be
   *  read back from it; returned here for convenience. */
  collections: ResolvedCollection[];
  /** Stable authorization id this commitment was signed under. All members of one
   *  submission set MUST share it (and the issuer), or the node refuses the mix. */
  authorizationId: string;
  /** Which leaf signed this commitment. Recorded for auditing the no-reuse
   *  invariant; `-1` is never returned (leaf 0 is valid, and is the stable mode). */
  leafIndex: number;
}

/** What `submit()` returns: the node's response plus one handle per prepared
 *  commitment, in the SAME order they were passed in. */
export interface SubmitResult {
  response: IssueResponse;
  /** One serializable handle per submitted commitment, index-aligned with the
   *  input array. Persist each and pass it to `resolveEmission()` later. */
  handles: EmissionHandle[];
}

export interface IssueResult {
  response: IssueResponse;
  /**
   * One entry per `leaves`-declared collection subject: its descriptor and its leaf
   * hashes, in leaf order.
   *
   * Returned for convenience: the same descriptor ships signed inside the certificate,
   * ordered, so these values can also be read back from there and an inclusion proof
   * rebuilt from the certificate alone. They are what a `verification-package/1` §11
   * carries. What is NOT recoverable anywhere is the leaf material behind each salted
   * digest — proving a member belongs still requires holding that member.
   */
  collections: ResolvedCollection[];
  commitment: LooseCommitment;
  authorizationId: string;
  /** Serializable handle of THIS emission. Persist it and pass it to
   *  `resolveEmission` later to check settlement + build the package without
   *  re-emitting (exactly one node operation per certificate). See EmissionHandle. */
  handle: EmissionHandle;
}

/**
 * A serializable handle of ONE emission (`emitCertificate`). The issuer persists
 * this as an opaque blob and hands it back to `resolveEmission` later to check the
 * certificate's settlement and build the verification-package — WITHOUT re-emitting.
 *
 * Why the SDK owns this: every issuer whose settlement is asynchronous faces the
 * same need — emit once, then resume. Without a handle, an issuer either blocks a
 * request waiting for settlement, or re-emits on every retry (a duplicate node
 * operation per attempt for the SAME certificate). The handle carries the two
 * pieces the node NEVER returns (independence_ref is derived from the client-held
 * capacity_evidence; the commitment_index positions it in the accepted set) so a
 * later process — even after a restart — can finish the job from the blob alone.
 *
 * Treat it as opaque; its shape may gain fields. It contains no secret (the
 * capacity_evidence is public), so it is safe to store next to the certificate.
 */
export interface EmissionHandle {
  /** The node operation to poll. The ONE operation for this certificate. */
  operationId: string;
  /**
   * The server's own id for this operation, as the node reported it at submit.
   *
   * The SDK still POLLS `operationId` (it talks only to the node), but a read
   * proof must sign THIS one: the server routes on it, and having both halves of the
   * read chain cover the id the server itself uses removes the only thing that would
   * otherwise have to be trusted — a node-declared mapping between its local alias
   * and the upstream id. With one id there is no mapping to declare and none to
   * believe.
   *
   * Absent for a member that was not accepted upstream (there is no service-side
   * operation to read).
   */
  upstreamOperationId?: string;
  /** Evidence digest bound into independence.proof/1 (the durable proof ref). */
  independenceRef: string;
  /** This commitment's index in the accepted set (for the inclusion proof). */
  commitmentIndex: number;
  /** The public capacity.evidence/1 the node never returns — needed to assemble
   *  the package. Public (no secret), safe to persist. */
  capacityEvidence: unknown;
  /** The signed base_certificate. `resolveEmission` puts it into the package so a
   *  verifier can reach INDEPENDENT_VALID and bind to the original material. */
   baseCertificate?: unknown;
  /** Descriptor + leaf hashes per collection subject. The descriptor travels
   *  signed inside the certificate; these are kept so the issuer can build
   *  inclusion proofs, which need the ordered leaf hashes. */
  collections?: ResolvedCollection[];
}

/** The half of an `EmissionHandle` CERTCRYPT can hand back, as the recovery
 *  endpoint returns it.
 *
 *  Four fields. The handle's other three come from the caller; two of them hold
 *  what only the issuer's certificate carries:
 *
 *    - `baseCertificate` — the issuer minted and signed it; only its digest ever
 *      crossed the boundary. Nothing server-side to return.
 *    - `collections` — descriptors and leaf hashes travel signed inside that
 *      base certificate, which CERTCRYPT never receives. They are read back
 *      from the certificate the issuer holds, and from nowhere else.
 *
 *  So recovery is a JOIN, not a download: this half plus the certificate the
 *  issuer still holds. An issuer that lost BOTH cannot reconstruct the emission
 *  from any endpoint. */
export interface RecoveredHandleFragment {
  operationId: string;
  independenceRef: string;
  /** Null until the emission settles: the index lives in the Proof of
   *  Independence, which does not exist before then. */
  commitmentIndex: number | null;
  capacityEvidence: unknown;
}

/**
 * Rebuild an `EmissionHandle` from a recovered fragment plus the issuer-held
 * material.
 *
 * WHY THIS EXISTS RATHER THAN A PLAIN OBJECT LITERAL. The one dangerous mistake
 * in recovery is supplying a `commitmentIndex` when the fragment has none —
 * defaulting it to 0, say, because the type demands a number. That produces a
 * handle that looks complete and yields an inclusion proof that verifies against
 * NOTHING: the index is a position in the Merkle leaf order, and the wrong
 * position is not a near miss. So a partial fragment is refused here, loudly,
 * instead of becoming an artifact that fails far away.
 *
 * Call it only for fragments whose emission has settled. For the rest, keep
 * polling: the endpoint says when.
 */
export function emissionHandleFromRecovery(
  fragment: RecoveredHandleFragment,
  issuerHeld: {
    baseCertificate: unknown;
    collections?: ResolvedCollection[];
    upstreamOperationId?: string;
  }
): EmissionHandle {
  if (fragment.commitmentIndex === null || fragment.commitmentIndex === undefined) {
    throw new Error(
      "cannot rebuild an EmissionHandle from a partial fragment: commitmentIndex " +
        "is null, which means the emission has not settled and its Merkle position " +
        "does not exist yet. Poll until it settles, then recover again — never " +
        "substitute a placeholder index: the inclusion proof it produces verifies " +
        "against nothing."
    );
  }
  return {
    operationId: fragment.operationId,
    upstreamOperationId: issuerHeld.upstreamOperationId,
    independenceRef: fragment.independenceRef,
    commitmentIndex: fragment.commitmentIndex,
    capacityEvidence: fragment.capacityEvidence,
    baseCertificate: issuerHeld.baseCertificate,
    collections: issuerHeld.collections,
  };
}

/** Terminal/interim outcome of `resolveEmission`. */
export type EmissionResolution =
  | { state: "independent"; verificationPackage: VerificationPackage; independenceRef: string }
  | {
      state: "pending";
      nodeState: string;
      /** The settlement window the node expects to settle this operation in, when it
       *  reported one. A reconciler should schedule its next call around
       *  `settlementWindow.expected_settled_by` (or `target_close_by` when the
       *  node reports no expected settlement instant) instead of polling blindly.
       *  Operational only — never verifier-evaluated, and it carries no cost figure
       *  (see {@link SettlementWindowEstimate}). */
      settlementWindow?: SettlementWindowEstimate;
      /** True when `expected_settled_by` (or, without it, `target_close_by`) has
       *  already passed and the operation is still not settled: it is running LATE. Lets an issuer surface "your operation is
       *  delayed" instead of an indefinite spinner. */
      overdue?: boolean;
    }
  | { state: "rejected"; nodeState: string }
  // The accepted operation can no longer reach Independent and consumed nothing
  // (submission-set/1 §11.1). Terminal; the certificate stays Issued, and a new
  // emission under a fresh authorization is the way to Independent.
  | { state: "expired"; nodeState: string; reasonCode: string };

/**
 * The default `valid_until` an activation asks for: a far-future bound for the LEVEL-1 BINDING's validity window —
 * not for a commitment.
 *
 * These are different clocks and only one is rate-limited by the rules-domain: an
 * authorization binding legitimately outlives any single issuance (re-minting it
 * per emission would produce a new authorization_id every restart), while a
 * capacity commitment must expire at exactly `issued_at + domain TTL`. Using this
 * value for a commitment produces certificates the verifier rejects; see
 * COMMITMENT_TTL_SECONDS below.
 */
export const FAR_FUTURE = "2100-01-01T00:00:00Z";


/**
 * Capacity-commitment TTL, in seconds, per rules-domain.
 *
 * A PUBLIC RULE of the domain, not an issuer setting. The verifier requires
 * `expires_at === issued_at + ttl` (COMMITMENT_TTL_VALID) precisely so an issuer
 * cannot widen its own window, and the issuance service enforces the same equality at
 * submit — so a wrong value is refused at issuance instead of surfacing months
 * later, in someone else's hands, on a certificate the issuer believed was good.
 *
 * Mirrors `commitment_ttl_seconds` in the verifier toolkit's per-environment
 * config. An unknown rules_version returns undefined and issuance FAILS: there is
 * no defensible default, and a far-future fallback (year 2100) would be
 * exactly the self-inflated window the rule exists to block.
 */
const COMMITMENT_TTL_SECONDS: Readonly<Record<string, number>> = Object.freeze({
  "rules/2026-01": 86_400,
  "rules/conformance": 2_592_000,
});

/**
 * The rules domains this SDK implements.
 *
 * Not configuration. `rules_version` is carried in every artifact this SDK emits
 * and covered by its signatures, and what it asserts is that the artifact was
 * produced under that exact normative body — its subject-profile
 * canonicalizations, its commitment constructions with their exact preimages, its
 * signature algorithms, its settlement contract. This SDK does not read those
 * from anywhere: they are compiled in (see crypto/canonical-subject.ts,
 * crypto/collection-merkle.ts). So it implements one normative body, and the
 * honest thing is to say which.
 *
 * Emitting under a rules domain this SDK does not implement is the failure mode
 * nothing downstream catches: the artifact verifies perfectly — signatures valid,
 * digests matching, settlement real — while attesting to behavior that never
 * happened. A verifier cannot detect it, because there is nothing malformed to
 * detect. Hence the refusal is here, at emission, where it is still possible
 * (`rules-domain/1` §14.2).
 *
 * Adding an entry means having implemented that rules domain, not having decided
 * to support it.
 */
export const SUPPORTED_RULES_VERSIONS: readonly string[] = Object.freeze([
  "rules/2026-01",
  "rules/conformance",
]);

/**
 * Rules domains registered at runtime, on top of the published ones.
 *
 * A deployment may run under a rules domain it registers at runtime instead of
 * one from the published list. The domain then comes from whoever runs the SDK,
 * never from this package: the shape is public, a deployment's values are its
 * own.
 *
 * This does NOT relax the gate. Registering a domain asserts the same thing
 * `SUPPORTED_RULES_VERSIONS` asserts — that this SDK implements that normative
 * body — and the assertion is then made by whoever registers it. An unregistered
 * domain is still refused, which is what `rules-domain/1` §14.2 requires.
 */
const runtimeRulesVersions = new Set<string>();

/**
 * Register a rules domain this SDK implements but does not publish.
 *
 * For a deployment that runs under its own rules domain. Call it before constructing
 * `Certcrypt`: the gate runs at construction.
 *
 * Only accepts a domain whose canonicalization and settlement semantics this SDK
 * already implements — i.e. one that differs from a published domain in WHERE it
 * settles, not in HOW artifacts are formed. Registering anything else produces
 * artifacts that verify correctly and attest to behavior that never happened,
 * which is precisely what the gate exists to prevent.
 */
export function registerRulesDomain(rulesVersion: string): void {
  if (typeof rulesVersion !== "string" || rulesVersion.length === 0) {
    throw new Error("Certcrypt: registerRulesDomain requires a non-empty rules_version");
  }
  if (!rulesVersion.startsWith("rules/")) {
    throw new Error(
      `Certcrypt: rules_version must start with "rules/", got "${rulesVersion}"`,
    );
  }
  runtimeRulesVersions.add(rulesVersion);
}

/** Every rules domain this SDK will emit under: published + registered. */
function implementedRulesVersions(): string[] {
  return [...SUPPORTED_RULES_VERSIONS, ...runtimeRulesVersions];
}

/**
 * The subject profiles this SDK can canonicalize, mirroring
 * crypto/canonical-subject.ts.
 *
 * Mirrors crypto/canonical-subject.ts, which is the only place that turns a
 * subject into committed bytes: a profile absent there cannot be emitted,
 * whatever else in this package mentions it. A rules domain may admit profiles an
 * SDK does not implement, and passing one is refused rather than approximated —
 * canonicalizing a subject under the wrong profile yields a commitment that is
 * well-formed and wrong, which is exactly the class of error §14.2 exists to
 * prevent.
 */
const IMPLEMENTED_SUBJECT_PROFILES: readonly string[] = Object.freeze([
  "subject.binary/1",
  "subject.text/1",
  "subject.email/1",
  "subject.collection/1",
  "subject.ai-decision/1",
  "subject.context-snapshot/1",
]);

/**
 * Fail closed unless this SDK implements the rules domain it is asked to emit
 * under. Called at construction, so the refusal lands before any signing key or
 * capacity is touched.
 */
function assertRulesDomainImplemented(rulesVersion: string): void {
  if (implementedRulesVersions().includes(rulesVersion)) return;
  throw new Error(
    `Certcrypt: this SDK does not implement rules_version "${rulesVersion}". ` +
      `It implements: ${implementedRulesVersions().join(", ")}. ` +
      "rules_version is not a parameter: it asserts, in every artifact emitted " +
      "and under its signatures, that the artifact was produced under that exact " +
      "normative body. Emitting under rules this SDK does not implement would " +
      "produce artifacts that verify correctly and attest to behavior that never " +
      "happened, which no verifier can detect (rules-domain/1 §14.2). Use a " +
      "rules_version this SDK implements, or an SDK that implements that one.",
  );
}

/**
 * PRIVATE signing-domain separators for the issuer↔node↔issuance-service channel.
 *
 * These are NOT public protocol identifiers. No normative spec defines them, no
 * verifier evaluates them, and a conforming third-party implementation never has
 * to reproduce them: they are a bilateral contract between an issuer and the
 * issuance service it talks to. What they buy is domain separation — a read signature must never be
 * valid as an activation, or as a commitment, with the same key.
 *
 * The `:` form is deliberate. The normative artifacts are all shaped
 * `name.thing/<version>` (`capacity.commitment/1`, `subject.text/1`,
 * `independence.proof/1`), so a separator in that same shape would read as a spec
 * identifier to anyone scanning this file — and someone evaluating an
 * implementation could reasonably conclude they had to reproduce it. The colon
 * form cannot be mistaken for one.
 *
 * They stay versioned even though nothing parses the `:1`: the whole string is
 * compared as opaque bytes, so the suffix is free today and gives a clean exit if
 * a message ever changes shape — a `:2` domain makes old and new signatures
 * mutually invalid by construction rather than silently sharing a domain.
 *
 * The CERTCRYPT service verifies these exact strings, so both sides MUST stay in
 * step: changing one alone turns every read into a 401 and every activation into a
 * rejected possession proof.
 */
const PRIVATE_SIGNING_DOMAIN_READ = "certcrypt:read:2";
const PRIVATE_SIGNING_DOMAIN_ACTIVATE = "certcrypt:activate:1";

/** The bytes both halves of a read chain sign: domain, the issuer's per-read
 *  challenge, and the resource. Exported for tests. */
export function readMessage(challenge: string, resource: string): string {
  return `${PRIVATE_SIGNING_DOMAIN_READ}|${challenge}|${resource}`;
}

function toRfc3339Seconds(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** Derive a stable authorization id from the binding: `auth:` followed by the
 *  first 32 hex characters of its authorized root. Kept opaque; the evidence
 *  carries it only as an operation-scoped pseudonym. */
function deriveAuthorizationId(binding: SignedLevel1Binding): string {
  const root = binding.level1_binding.holder_key_set_root ?? "";
  return `auth:${root.slice(0, 32)}`;
}

export class Certcrypt {
  private readonly client: CertcryptNodeClient;
  private readonly keySet: HolderKeySet;
  private readonly opts: CertcryptOptions;
  private readonly mode: IssuerMode;
  private readonly leafStore: LeafStore | null;
  /** Optional cache for the Level-1 binding (see BindingStore). null = no caching,
   *  which is fully supported: the SDK re-activates from `integrationKey` instead. */
  private readonly bindingStore: BindingStore | null;
  private signedLevel1: SignedLevel1Binding | null;
  private poolId: string | undefined;
  /** The canonical holder_id the ACTIVATION bound to this integration. The
   *  emission is attributed to it, so emission MUST use it (not a
   *  caller-configured value). Learned from activate(); falls back to
   *  opts.holderId only when a pre-obtained signedLevel1 skips activation. */
  private holderId: string | undefined;
  /** Composite cert-signing key for verifiable issuance. Either injected
   *  (opts.issuerKey) or derived lazily from the master seed on first issue(). */
  private issuerKeyCached: IssuerKey | null;

  constructor(opts: CertcryptOptions) {
    // Before anything else: this SDK implements one normative body, and refusing
    // here means the refusal lands before a key is derived, capacity is touched or
    // an artifact exists to be mistaken for a valid one.
    assertRulesDomainImplemented(opts.rulesVersion);
    this.opts = opts;
    this.mode = opts.mode ?? "stable";
    const treeSize = opts.treeSize ?? (this.mode === "stable" ? 1 : 4096);
    if (this.mode === "unlinkable" && treeSize < 2) {
      throw new Error("unlinkable mode needs a treeSize >= 2 (a distinct leaf per cert)");
    }
    if (
      opts.commitmentTtlSeconds !== undefined &&
      !(Number.isInteger(opts.commitmentTtlSeconds) && opts.commitmentTtlSeconds > 0)
    ) {
      throw new Error(
        "commitmentTtlSeconds must be a positive whole number of seconds: the verifier " +
          "requires expires_at === issued_at + ttl, and a TTL of zero or less yields a " +
          "commitment that is already expired",
      );
    }
    // No default store. The leaf bookkeeping has to survive restarts, and an
    // in-memory default would restart at zero and reuse every leaf it handed out
    // — the one failure no verifier can detect.
    if (this.mode === "unlinkable" && !opts.leafStore) {
      throw new Error(
        'mode "unlinkable" requires a leafStore: each commitment must be signed with a ' +
          "leaf never used before, and that bookkeeping has to survive restarts",
      );
    }
    this.keySet = HolderKeySet.fromMasterSeed(opts.keysetSeed, treeSize);
    this.leafStore = this.mode === "unlinkable" ? opts.leafStore! : null;
    // No default store: unlike the leaf counter, an absent binding cache costs only
    // one request per start (the SDK re-activates), so silently picking a location
    // for the integrator would trade a real deployment decision for nothing.
    this.bindingStore = opts.bindingStore ?? null;
    this.signedLevel1 = opts.signedLevel1 ?? null;
    this.poolId = opts.poolId;
    this.holderId = opts.holderId;
    this.issuerKeyCached = opts.issuerKey ?? null;

    const clientOpts: NodeClientOptions = {
      baseUrl: opts.nodeBaseUrl,
      pool_id: opts.poolId,
      // Self-verifying issuer-auth: each request to the node carries a fresh proof
      // the node verifies OFFLINE (no token lookup, no call to the issuance service). Built from the
      // cached Level-1 binding + a leaf disclosure + a possession signature over a
      // fresh challenge. Null until activated (the binding is minted on first emit).
      issuerAuthProof: (request) => this.buildIssuerAuthProof(request),
      // The client polls by node-local id; the proof must cover the id the
      // issuance service routes on. The issuer knows both because the node reported the upstream id
      // at submit, so it translates here — nobody has to declare the mapping over
      // the wire, and nobody has to trust one.
      issuerReadProof: (resource: string) =>
        this.buildIssuerReadProof(this.upstreamIds.get(resource) ?? resource),
      // Learns the upstream id of a member the node delivered late, so the
      // next read signs the id the server routes on.
      onUpstreamOperationId: (operationId: string, upstream: string) => {
        if (!this.upstreamIds.has(operationId)) this.upstreamIds.set(operationId, upstream);
      },
    };
    if (opts.fetch) clientOpts.fetch = opts.fetch;
    if (opts.retry) clientOpts.retry = opts.retry;
    this.client = new CertcryptNodeClient(clientOpts);
  }

  /**
   * Build the `x-certcrypt-issuer-auth` header value: base64(JSON) of
   * { signed_level1, disclosure, challenge, possession_b64 }. Returns null if not
   * yet activated (no binding to present). The challenge is fresh per call
   * (timestamp + random), binding the possession signature to this request; the
   * node accepts it once and downstream request_id idempotency neutralizes replay.
   */
  private buildIssuerAuthProof(request: IssuerAuthRequest): string | null {
    if (!this.signedLevel1) return null;
    // Leaf 0 in either mode: this proof goes to the node with the request and
    // never into an artifact.
    const leafIndex = 0;
    const challenge = `${Date.now()}.${Buffer.from(
      globalThis.crypto.getRandomValues(new Uint8Array(16)),
    ).toString("base64")}`;
    // Signed together with the request it is for (see issuerAuthMessage).
    const possession = this.keySet.sign(
      leafIndex,
      Buffer.from(issuerAuthMessage(challenge, request), "utf8"),
    );
    const proof = {
      signed_level1: this.signedLevel1,
      disclosure: this.keySet.disclosure(leafIndex),
      challenge,
      possession_b64: Buffer.from(possession).toString("base64"),
    };
    return Buffer.from(JSON.stringify(proof), "utf8").toString("base64");
  }

  /** node-local operation id → the server's id for it, learned at submit. Only ever
   *  holds emissions THIS process made; a handle restored from storage carries its
   *  `upstreamOperationId` and is registered on use. */
  private readonly upstreamIds = new Map<string, string>();

  /**
   * Build the `x-certcrypt-issuer-read` header value: base64(JSON) of
   * { signed_level1, disclosure, challenge, possession_b64 }, where the possession
   * signature covers `certcrypt:read:2|<challenge>|<resource>` (a PRIVATE signing
   * domain, not a spec id). The challenge is fresh per call and the issuance
   * service spends it: the node that relays this half cannot replay it later to
   * read on its own initiative.
   *
   * WHY A READ NEEDS THIS. A submit proves who its issuer is from the inside —
   * every certificate carries `capacity_evidence` this key set signed. A read
   * carries no such artifact, so the scope has to come from somewhere else, and
   * the only sound answer is a signature: the issuer signs the exact resource it
   * is asking for, so the server derives the scope from WHO SIGNED rather than from
   * whoever transported the request. A node therefore cannot read anything unless
   * its issuer actually asked for it.
   *
   * Returns null before activation (no binding to present yet).
   */
  private buildIssuerReadProof(resource: string): string | null {
    if (!this.signedLevel1) return null;
    const leafIndex = 0;
    const challenge = `${Date.now()}.${Buffer.from(
      globalThis.crypto.getRandomValues(new Uint8Array(16)),
    ).toString("base64")}`;
    const message = readMessage(challenge, resource);
    const possession = this.keySet.sign(leafIndex, Buffer.from(message, "utf8"));
    const proof = {
      signed_level1: this.signedLevel1,
      disclosure: this.keySet.disclosure(leafIndex),
      challenge,
      possession_b64: Buffer.from(possession).toString("base64"),
    };
    return Buffer.from(JSON.stringify(proof), "utf8").toString("base64");
  }

  /** The holder_key_set_root to supply at onboarding (or that the
   *  activation binds via TOFU). Public value derived from the secret seed. */
  keysetRoot(): string {
    return this.keySet.root;
  }

  /** The cached Level-1 binding (present after activation), or null before it.
   *  Public (no secret). Persisting it is an OPTIMIZATION, not a requirement — a
   *  restart re-activates from `integrationKey`. To cache it, prefer a `bindingStore`
   *  (it also carries `holderId`/`poolId`, which a bare binding does not). */
  binding(): SignedLevel1Binding | null {
    return this.signedLevel1;
  }

  /**
   * Activate the integration WITHOUT issuing anything.
   *
   * Activation is normally invisible: the first `issue()` does it on the way past,
   * so a first issuance is an ordinary issuance that also happens to activate.
   * Call this to redeem the integration key and confirm the credentials at deploy
   * time, before any certificate exists. Reaching `Independent` is a separate,
   * later event.
   *
   * It redeems the key against the server and caches the binding. It does NOT create
   * a certificate, does NOT anchor anything, and consumes NO capacity: issuance is
   * a separate request. Idempotent — safe to call on every start, and a no-op once
   * bound. Typical use is a startup or readiness hook:
   *
   *   await certcrypt.activate();   // deploy time: claim the key
   *   …
   *   await certcrypt.issue({ … }); // later: the real certificate
   */
  async activate(): Promise<SignedLevel1Binding> {
    return this.ensureActivated();
  }

  /**
   * Ensure we hold a Level-1 binding. Resolution order, each step a fallback of the
   * previous: (1) already in memory, (2) the `bindingStore` cache, (3) activate from
   * `integrationKey`. Idempotent — a second call is a no-op once bound.
   *
   * Step 3 is what makes a COLD RESTART work with nothing persisted: the keyset root
   * is re-derived from `keysetSeed`, so re-presenting the same `integrationKey` is an
   * idempotent replay the server answers with the same binding. The store only saves the
   * round-trip; it is never required for correctness, so a load failure is swallowed.
   */
  async ensureActivated(): Promise<SignedLevel1Binding> {
    if (this.signedLevel1) return this.signedLevel1;

    // (2) Cache hit: adopt the binding AND the two identifiers activation bound to
    // it. A store that returned a binding without them would leave issue() throwing.
    if (this.bindingStore) {
      try {
        const cached = await this.bindingStore.load();
        if (cached?.binding) {
          this.signedLevel1 = cached.binding;
          this.holderId = cached.holderId;
          if (!this.poolId) this.poolId = cached.poolId;
          return this.signedLevel1;
        }
      } catch {
        // A cache is never fatal: fall through and re-activate from the key.
      }
    }

    if (!this.opts.integrationKey) {
      throw new Error(
        "not activated: provide `integrationKey`. Keep it in config alongside " +
          "`keysetSeed` and supply it on every start — it is not consumed by use. " +
          "Issue one at https://console.certcrypt.com. A pre-obtained " +
          "`signedLevel1` also works, but then `holderId` must be set.",
      );
    }
    // Prove we own the root we are asking the server to bind. Activation travels
    // THROUGH A NODE, so an unsigned root would be just a body field in transit:
    // binding it has to require proof that the presenter actually holds the key
    // set. Signing `certcrypt:activate:1|<code>|<root>` with a leaf of that very
    // key set is something only the holder of the seed can do, which is what ties
    // the one-time code to THIS issuer's identity and no other.
    const activationLeafIndex = 0;
    const activationMessage =
      `${PRIVATE_SIGNING_DOMAIN_ACTIVATE}|${this.opts.integrationKey}|${this.keySet.root}`;
    const activationPossession = this.keySet.sign(
      activationLeafIndex,
      Buffer.from(activationMessage, "utf8"),
    );
    const res = await this.client.activate({
      code: this.opts.integrationKey,
      holderKeySetRoot: this.keySet.root,
      keySetDisclosure: this.keySet.disclosure(activationLeafIndex),
      keySetPossessionB64: Buffer.from(activationPossession).toString("base64"),
      rulesVersion: this.opts.rulesVersion,
      systemRootFingerprint: this.opts.systemRootFingerprint,
      // No valid_from: the issuance service fixes it, and a same-root replay
      // answers with the authorization bound at first activation, so restarts
      // reuse one authorization without the SDK choosing any date.
      validUntil: this.opts.validUntil ?? FAR_FUTURE,
    });
    this.signedLevel1 = res.signedLevel1;
    if (!this.poolId) this.poolId = res.poolId;
    // The activation is authoritative for the (holder_id, pool_id) emission is
    // attributed to — always adopt the returned holder_id, overriding any configured
    // one, so emission is attributed to the identity the activation bound.
    this.holderId = res.holderId;

    if (this.bindingStore) {
      try {
        await this.bindingStore.save({
          binding: res.signedLevel1,
          holderId: res.holderId,
          poolId: res.poolId,
        });
      } catch {
        // Persisting is an optimization; a failure only costs a round-trip next start.
      }
    }
    return this.signedLevel1;
  }

  /** The composite cert-signing key: injected (opts.issuerKey) or derived once
   *  from the master seed, domain-separated from the operation-key tree. The
   *  issuer never handles it; it is reconstructed from the seed it already gave. */
  private resolveIssuerKey(): IssuerKey {
    if (!this.issuerKeyCached) {
      const id = this.opts.issuerKeyId ?? `issuer:${this.keySet.root.slice(0, 32)}`;
      this.issuerKeyCached = deriveIssuerKey(this.opts.keysetSeed, id);
    }
    return this.issuerKeyCached;
  }

  /**
   * Issue a certificate over `input.subjects` — the ONE issuance surface, verifiable
   * by construction. Activates on first use, then: derives the composite signing
   * key from the seed, canonicalizes each subject byte-identically to the verifier,
   * mints a SIGNED base_certificate whose commitment is derived FROM the material(s)
   * (never an opaque caller digest), and submits it toward Independent. A third
   * party holding the original material + the returned proof can verify the binding
   * OFFLINE. In "stable" mode reuses leaf 0; in "unlinkable" mode pulls a fresh leaf.
   *
   * The returned `IssueResult.handle` (with `baseCertificate`) is the serializable
   * operation handle: persist it and call `resolveEmission(handle)` later to poll THIS one
   * operation and build the verification-package — never re-emitting.
   */
  async issue(input: IssueInput): Promise<IssueResult> {
    // issue() is prepare() + submit() for N=1, and stays the surface almost every
    // integration should use: one certificate, one request, nothing to persist
    // between the two halves and no leaf left in limbo if the send fails.
    const prepared = await this.prepare(input);
    const { response, handles } = await this.submit([prepared], {
      ...(input.settlementPreferences
        ? { settlementPreferences: input.settlementPreferences }
        : {}),
    });
    return {
      response,
      commitment: prepared.commitment,
      authorizationId: prepared.authorizationId,
      handle: handles[0]!,
      collections: prepared.collections,
    };
  }

  /**
   * Sign ONE certificate and return its commitment WITHOUT sending it, so several
   * can be submitted together with `submit()`.
   *
   * WHY IT EXISTS. N unrelated certificates sent one at a time carry the
   * per-submission overhead N times; the same N prepared and submitted in a single
   * request carry it once. For a batch that is the whole saving: the node accepts
   * N members in one request, and this is the step before the send.
   *
   * WHAT IT COSTS. This is where everything irreversible happens: the
   * base_certificate is signed and the leaf and operation salt are spent. Sending
   * is not what consumes them. In "unlinkable" mode a prepared commitment that is
   * never submitted leaves its leaf spent for good — the allocator is monotone on
   * purpose (`LeafStore` has no `release()`), because recycling would reintroduce a
   * reuse no verifier can detect. Losing a leaf costs one slot in a large key set;
   * reusing one silently destroys the unlinkability the mode exists for. In
   * "stable" mode leaf 0 is reused by design and nothing is lost.
   *
   * So: to retry a failed send, call `submit()` again with the commitment you
   * already hold. Never re-`prepare()` the same material — that signs a second
   * commitment for one certificate.
   *
   * Validation is identical to `issue()` (same non-empty subjects, implemented
   * profiles, system_id, root_id, pool/holder, TTL) because both run this method.
   *
   * All members of one submission set must share issuer and authorization; every
   * commitment from the same instance does, so prepared commitments can be mixed
   * freely — `submit()` rejects a mismatch before spending a request.
   */
  async prepare(input: IssueInput): Promise<PreparedCommitment> {
    const signedLevel1 = await this.ensureActivated();
    const poolId = this.poolId;
    if (!poolId) throw new Error("no pool_id (set poolId or obtain it from activation)");
    const holderId = this.holderId;
    if (!holderId) {
      throw new Error(
        "no holder_id: it is learned from activation; provide an integrationKey, " +
          "or set holderId in options when supplying a pre-obtained signedLevel1",
      );
    }
    const rootId = this.opts.systemRootFingerprint;
    if (!rootId) {
      throw new Error("issue() requires systemRootFingerprint (the Independent root_id)");
    }
    // An empty system_id signs fine and is REJECTED by every conformant verifier
    // (BASE_CERTIFICATE_STRUCTURE_VALID). Catch it at issuance, not at verification.
    if (!this.opts.systemId) {
      throw new Error(
        'issue() requires systemId (the system domain id, e.g. "certcrypt"). ' +
          "Without it the certificate carries an empty payload.system_id and every " +
          "conformant verifier REJECTS it."
      );
    }
    if (!Array.isArray(input.subjects) || input.subjects.length === 0) {
      throw new Error("issue() requires a non-empty subjects[] set");
    }
    // A rules domain may admit subject profiles this SDK does not implement.
    // Canonicalizing under the wrong profile produces a commitment that is
    // well-formed and wrong, so an unimplemented profile is refused rather than
    // approximated (rules-domain/1 §14.2).
    for (const [index, subject] of input.subjects.entries()) {
      const profile = (subject as {profile?: string}).profile;
      if (profile !== undefined && !IMPLEMENTED_SUBJECT_PROFILES.includes(profile)) {
        throw new Error(
          `issue(): subject[${index}] declares profile "${profile}", which this SDK ` +
            `does not implement. It implements: ${IMPLEMENTED_SUBJECT_PROFILES.join(", ")}. ` +
            "The profile fixes how the subject is canonicalized and committed to, so " +
            "emitting under one this SDK cannot canonicalize would bind the certificate " +
            "to a commitment no conforming verifier reproduces.",
        );
      }
    }

    const issuedAt = input.issuedAt ?? toRfc3339Seconds(new Date());
    // The verifier requires expires_at == issued_at + rules-domain TTL. An explicit
    // input.expiresAt still wins (advanced callers), then an explicit TTL, then the
    // domain's published one. There is no far-future fallback: it would produce a
    // certificate the verifier rejects, silently, and the issuer would only find out
    // when a third party tried to verify it.
    // `??`, not `||`: only an absent value falls back. A zero TTL is refused at
    // construction, so nothing here has to tell 0 apart from "unset".
    const ttlSeconds =
      this.opts.commitmentTtlSeconds ?? COMMITMENT_TTL_SECONDS[this.opts.rulesVersion];
    if (input.expiresAt === undefined && ttlSeconds === undefined) {
      throw new Error(
        `issue(): no commitment TTL for rules_version "${this.opts.rulesVersion}". ` +
          "The TTL is a public rule of the rules-domain and the verifier requires " +
          "expires_at === issued_at + ttl, so it cannot be guessed. Pass " +
          "commitmentTtlSeconds explicitly, or use a rules_version this SDK knows.",
      );
    }
    const expiresAt =
      input.expiresAt ?? computeExpiresAt(issuedAt, ttlSeconds as number);
    const authorizationId = deriveAuthorizationId(signedLevel1);

    // Generated up front: it is the collection salt, so it must exist before the
    // subjects are resolved (subject.collection/1 §8).
    const nonceHex = generateNonceHex();
    const { subjects: resolvedSubjects, collections } = resolveCollectionSubjects(
      input.subjects,
      nonceHex
    );

    // Spent HERE, at signing: in unlinkable mode this leaf never comes back.
    const leafIndex = this.mode === "stable" ? 0 : await this.leafStore!.nextLeaf();
    const operationSalt = randomBytes(32);

    const { commitment, minted } = this.client.mintVerifiableCertificate({
      subjects: resolvedSubjects,
      issuerKey: this.resolveIssuerKey(),
      target: { mode: "independent-capable", root_id: rootId },
      anchor: {
        issued_at: issuedAt,
        nonce_hex: nonceHex,
        system_id: this.opts.systemId,
        rules_version: this.opts.rulesVersion,
      },
      signedLevel1,
      holderId,
      // The pool resolved for THIS issuer: configured, or learned at activation.
      // The client was built before activation, so its own pool may be unset.
      poolId,
      authorizationId,
      evidenceFields: {
        // Defaults to "0" on purpose, and that is NOT a placeholder to fill in
        // later: an issuer cannot know what an issuance will consume. The value is
        // resolved server-side and is not final until the operation crystallizes,
        // so asking the caller for a number here would be asking for one it does
        // not have.
        //
        // Nothing reads this field: it is carried into the submission set and
        // persisted, but no gate or verifier check depends on it.
        //
        // The quantity the issuance really consumed comes back in the
        // `settlement_material` that the `independence_proof` binds — after
        // crystallization, when it is a fact rather than a forecast.
        consumed_quantity: input.consumedQuantity ?? "0",
        // Σ over the certificate's subjects of each subject's effective units (a
        // normal subject = 1; a subject.collection/1 = its declared_cardinality).
        // A multi-subject certificate therefore declares its TRUE subject count,
        // not 1 — a single-subject cert still declares "1". The node re-derives
        // this from the base_certificate and rejects a mismatch (fail-closed), so
        // the declaration cannot understate what the certificate actually carries.
        // An explicit override wins only for advanced callers that pre-computed it.
        declared_effective_units:
          input.declaredEffectiveUnits ?? sumEffectiveUnits(input.subjects),
        issued_at: issuedAt,
        expires_at: expiresAt,
      },
      keySet: this.keySet,
      leafIndex,
      operationSalt,
    });

    return {
      commitment,
      baseCertificate: minted.base_certificate,
      collections,
      authorizationId,
      leafIndex,
    };
  }

  /**
   * Submit prepared commitments as ONE submission set and return a handle for each.
   *
   * This is the request `prepare()` exists to fill: N members travel together and
   * amortize the per-submission overhead across all of them. It is
   * N-in-one-request, synchronous — not a time-window accumulation, so nothing is buffered and nothing is deferred.
   *
   * Handles come back in the SAME order as the input, each already correlated with
   * its member of the response, so a batch of N is as persistable as a single
   * emission: keep each handle and call `resolveEmission()` on it later.
   *
   * A retry re-sends these same commitments — the SDK never re-signs, because a
   * leaf must not be reused. If the send fails after signing, the leaves are
   * already spent (see `prepare()`); calling `submit()` again with the same array
   * is the correct move, and the node deduplicates on the request id.
   *
   * At most `MAX_SUBMISSION_SET_MEMBERS` (64) commitments make one set; more
   * throw `SubmissionSetTooLargeError` before anything is sent
   * (submission-set/1 §8.1). Split a larger batch into several `submit()` calls.
   */
  async submit(
    prepared: PreparedCommitment[],
    opts: { settlementPreferences?: SettlementPreferences; requestId?: string } = {},
  ): Promise<SubmitResult> {
    if (!Array.isArray(prepared) || prepared.length === 0) {
      throw new Error("submit() requires a non-empty prepared[] array");
    }
    // The producer refuses to build an over-bound set (submission-set/1 §8.1).
    assertSubmissionSetWithinBound(prepared.length);
    // Every member of one set must answer to the same issuer and authorization, or
    // the node refuses the whole request. Caught here so a mixed batch costs an
    // error rather than a round-trip — the commitments are already signed either
    // way, but the request is not spent.
    const authorizationId = prepared[0]!.authorizationId;
    for (const [index, item] of prepared.entries()) {
      if (item.authorizationId !== authorizationId) {
        throw new Error(
          `submit(): prepared[${index}] carries authorization_id ` +
            `"${item.authorizationId}" but prepared[0] carries "${authorizationId}". ` +
            "One submission set is one issuer under one authorization; the node " +
            "refuses a mixed set. Submit them as separate requests.",
        );
      }
    }

    const response = await this.client.issue({
      commitments: prepared.map((p) => p.commitment),
      ...(opts.requestId ? { request_id: opts.requestId } : {}),
      ...(opts.settlementPreferences
        ? {
            settlement_preferences: {
              window_profile: opts.settlementPreferences.windowProfile,
              fallback_policy: opts.settlementPreferences.fallbackPolicy ?? "reject",
            },
          }
        : {}),
    });

    // Correlate by commitment_index when the node reports one (a set of N comes
    // back indexed), falling back to positional order for a single member.
    const handles: EmissionHandle[] = prepared.map((item, position) => {
      const member =
        response.results?.find((r) => r.commitment_index === position) ??
        response.results?.[position];
      const operationId = member?.operation_id ?? "";
      if (!operationId) {
        // A whole-request failure — a transport error reaching the issuance service, or a
        // rejection before per-member evaluation — comes back with `results`
        // EMPTY and the reason in the top-level `state`. Reporting "no
        // operation_id" here hides that reason behind a symptom, which is how a
        // transient upstream failure ends up looking like a protocol bug —
        // typically under concurrency, where one request of several fails this way.
        const whole = (response as { state?: { state?: string; error?: string } }).state;
        if (whole?.state) {
          throw new CertcryptNodeError(
            `submit failed: ${whole.state}${whole.error ? ` — ${whole.error}` : ""}`,
            null,
            JSON.stringify(whole),
          );
        }
        throw new Error(
          `submit: node returned no operation_id for prepared[${position}] ` +
            `(results had ${response.results?.length ?? 0} entries and no top-level state)`,
        );
      }
      const upstreamOperationId =
        member?.state?.state === "accepted"
          ? (member.state as { upstream_operation_id?: string }).upstream_operation_id
          : undefined;
      if (upstreamOperationId) this.upstreamIds.set(operationId, upstreamOperationId);
      return {
        operationId,
        ...(upstreamOperationId ? { upstreamOperationId } : {}),
        independenceRef: evidenceDigestHex(item.commitment.capacity_evidence as any),
        commitmentIndex: member?.commitment_index ?? position,
        ...(item.collections.length > 0 ? { collections: item.collections } : {}),
        capacityEvidence: item.commitment.capacity_evidence,
        // The signed base_certificate — this is what makes the emission verifiable
        // against the original material. resolveEmission threads it into the package.
        baseCertificate: item.baseCertificate,
      };
    });

    return { response, handles };
  }

  /**
   * List the emissions this integration has in flight — neither independently
   * verifiable yet nor terminally refused.
   *
   * `resolveEmission` requires a handle and `getOperation` requires an id. An
   * issuer that lost both can still enumerate its in-flight emissions here: the
   * request is authenticated by the caller's own key, the read chain proves the
   * key-set root, and the server answers for that root's integration.
   *
   * Persisting the handle at emission remains the supported path; this method
   * makes a lost handle recoverable instead of a reason to re-emit.
   *
   * `since` is required and bounded server-side; check `truncated` before
   * treating the list as complete.
   */
  async listUnresolvedEmissions(
    since: string,
    limit?: number
  ): Promise<UnresolvedEmissions> {
    // A process that only RECOVERS (it did not emit) has no binding yet, so the
    // read would carry no issuer half and be refused. Activating first is
    // idempotent and a no-op once bound.
    await this.ensureActivated();
    return this.client.listUnresolvedEmissions(since, limit);
  }

  /**
   * Resolve an emission by the digest of the capacity evidence that produced it.
   *
   * The fallback when the node no longer knows the operation — it restarted with
   * an in-memory journal, or the issuer moved to another node. The digest is the
   * one identifier the issuer can always produce, because it recomputes it from
   * evidence it signed; the attempt id was never the issuer's and the node's
   * operation id belongs to a journal it may no longer be talking to.
   *
   * Not a weaker path: the read still carries both halves of the chain, and the
   * resource signed is the digest itself — which is stronger than signing an id
   * the node handed over, because the issuer can check what it means.
   *
   * Returns `pending` while the emission has not settled. Once it has, the full
   * `verification_package` is assembled from the proof and the settlement
   * material this read returns plus the handle the issuer kept
   * (`baseCertificate`, `capacityEvidence`, `commitmentIndex`); the inclusion
   * proof is derived from the proof's `consumed_commitment_ids`.
   */
  private async resolveByCommitment(
    handle: EmissionHandle,
    verificationContext: { rules_version: string; system_id: string },
  ): Promise<EmissionResolution> {
    const rec = await this.client.getEmissionByCommitment(handle.independenceRef);
    if (rec.status === "expired") {
      return { state: "expired", nodeState: rec.status, reasonCode: rec.reason_code ?? "expired" };
    }
    // Every other terminal status that is not independent_ready ends the
    // emission without a proof (insufficient_capacity, for one).
    if (rec.status !== "independent_ready" && isTerminalState(rec.status)) {
      return { state: "rejected", nodeState: rec.status };
    }
    // BOTH artifacts or nothing: a package missing the settlement material does
    // not verify, and returning a half-built one would fail later and further
    // away, where the cause is no longer visible.
    if (
      rec.status !== "independent_ready" ||
      !rec.independence_proof ||
      !rec.settlement_material
    ) {
      return { state: "pending", nodeState: rec.status };
    }

    // Everything the package needs is either in the handle the issuer kept
    // (`baseCertificate`, `capacityEvidence`, `commitmentIndex`) or derivable from
    // the proof itself (the inclusion proof comes from its
    // `consumed_commitment_ids`). The node contributed none of it — which is why
    // this path can return the same verdict, not a weaker one.
    const verificationPackage = this.client.assembleVerificationPackageFromProof({
      independenceProofB64: rec.independence_proof,
      settlementMaterialB64: rec.settlement_material,
      baseCertificate: handle.baseCertificate,
      capacityEvidence: handle.capacityEvidence,
      verificationContext,
      commitmentIndex: handle.commitmentIndex,
    });
    return {
      state: "independent",
      verificationPackage,
      independenceRef: handle.independenceRef,
    };
  }

  /**
   * Resolve a previously-emitted certificate from its handle: poll the ONE operation's
   * state (never re-emits) and, once independent_ready, build the full
   * verification-package/1 from the handle's own capacity_evidence + the node's
   * proof/settlement material. Returns:
   *   - { state: "independent", verificationPackage, independenceRef } once settled,
   *   - { state: "pending", nodeState } while it is still being settled (retry later),
   *   - { state: "expired", nodeState, reasonCode } when it can no longer settle,
   *   - { state: "rejected", nodeState } on any other terminal state
   *     (rejected, insufficient_capacity, replay_detected, pre_evaluation_rejected,
   *     submission_failed).
   *
   * `opts.wait` bounds the poll (default: a SINGLE status check — a reconciler
   * wants a quick "is it ready yet?", not a long block). Pass `maxAttempts` above
   * 1, `maxWaitMs`, or `strategy: "auto"` to wait inline; a wait that ends
   * without a terminal state reports `pending`, it does not throw.
   * `opts.verificationContext` supplies the published profile values
   * (rules_version + system_id) the package records; it defaults to this
   * instance's `rulesVersion` and `systemId`.
   */
  async resolveEmission(
    handle: EmissionHandle,
    opts: {
      /** The published profile values the package records. Default: this
       *  instance's `rulesVersion` and `systemId`. */
      verificationContext?: { rules_version: string; system_id: string };
      /** Poll scheduling. Omit for a single status check (the default). Supports the
       *  window-aware `auto` strategy, `maxWaitMs` and `onProgress` — see WaitOptions. */
      wait?: WaitOptions;
    } = {},
  ): Promise<EmissionResolution> {
    const verificationContext = opts.verificationContext ?? {
      rules_version: this.opts.rulesVersion,
      system_id: this.opts.systemId ?? "",
    };
    // Ensure the issuer is activated BEFORE polling: the node's operation reads
    // are issuer-authenticated (x-certcrypt-issuer-auth), and that header is built
    // from the cached Level-1 binding. A process that only RESOLVES a handle (e.g.
    // a separate process that did not emit in-process) has no binding yet → the
    // proof provider returns null → the node answers 401. Activating first (idempotent;
    // a no-op once bound) makes resolveEmission self-sufficient, exactly like issue().
    await this.ensureActivated();
    // A handle restored from storage (another process, a restart) carries the
    // upstream id but was never registered in-process. Register it before any read
    // so the proof signs the id the server routes on.
    if (handle.upstreamOperationId) {
      this.upstreamIds.set(handle.operationId, handle.upstreamOperationId);
    }
    // The node's operation id lives in THAT node's journal. A node restarted with
    // an in-memory journal, or a different node entirely (the model treats moving
    // as changing a URL, not migrating), answers 404 for an emission the issuance
    // service still holds.
    //
    // The capacity-evidence digest does not have that problem: the issuer
    // recomputes it from evidence it signed itself, and it identifies the emission
    // at the issuance service. So a 404 here is not the end of the road — it is the signal to
    // ask by the identifier that outlives the node.
    let rec;
    try {
      rec = await this.client.getOperation(handle.operationId);
    } catch (e) {
      if (!(e instanceof CertcryptNodeError && e.status === 404) || !handle.independenceRef) {
        throw e;
      }
      return await this.resolveByCommitment(handle, verificationContext);
    }
    let nodeState = rec.state.state;
    let expiredReason = rec.state.state === "expired" ? rec.state.reason_code : "expired";
    // The node's scheduling hint, carried through the optional wait below so the
    // pending result can report which window we are waiting on.
    let window = rec.settlement_window;

    // Optional bounded wait. Default: just the one check we already did — a
    // reconciler wants "is it ready yet?", not a block. When the caller DOES ask
    // to wait, its WaitOptions are passed through untouched, so the window-aware
    // scheduling (and `onProgress`) apply here exactly as on the client.
    const wantsWait =
      opts.wait !== undefined &&
      ((opts.wait.maxAttempts ?? 1) > 1 ||
        opts.wait.maxWaitMs !== undefined ||
        opts.wait.strategy === "auto");
    if (wantsWait && !isTerminalState(nodeState)) {
      try {
        const settled = await this.client.waitForOperation(handle.operationId, opts.wait!);
        nodeState = settled.state.state;
        if (settled.state.state === "expired") expiredReason = settled.state.reason_code;
        if (settled.settlement_window) window = settled.settlement_window;
      } catch (e) {
        // The wait timed out without a terminal state. That is NOT an error for
        // resolveEmission: the operation is still being settled and the handle is still
        // good. Fall through and report `pending` (with the window, so the caller
        // knows when to come back) rather than making the issuer handle a throw for
        // the ordinary "not ready yet" case. A 404 (wrong id) still propagates.
        if (e instanceof CertcryptNodeError && e.status === 404) throw e;
      }
    }

    if (nodeState === "expired") return { state: "expired", nodeState, reasonCode: expiredReason };
    // Every other terminal state that is not independent_ready ends the
    // emission without a proof: rejected, insufficient_capacity,
    // replay_detected, pre_evaluation_rejected, submission_failed.
    if (nodeState !== "independent_ready" && isTerminalState(nodeState)) {
      return { state: "rejected", nodeState };
    }
    if (nodeState !== "independent_ready") {
      // Hand back the node's own schedule so the caller can time its next check
      // instead of polling blindly — and can tell "settling normally" apart from
      // "late", which is what a stuck settlement actually looks like from here.
      const settlementWindow = window ?? rec.settlement_window;
      const overdue = isSettlementOverdue(settlementWindow, Date.now());
      return {
        state: "pending",
        nodeState,
        ...(settlementWindow ? { settlementWindow } : {}),
        ...(overdue ? { overdue: true } : {}),
      };
    }

    const verificationPackage = await this.client.buildVerificationPackage(handle.operationId, {
      // Client-held artifacts the server never returns: without them the package
      // cannot reach INDEPENDENT_VALID or bind to the original material.
      baseCertificate: handle.baseCertificate,
      capacityEvidence: handle.capacityEvidence,
      verificationContext,
      commitmentIndex: handle.commitmentIndex,
    });

    return { state: "independent", verificationPackage, independenceRef: handle.independenceRef };
  }

  /** Access the underlying low-level client (advanced: buildVerificationPackage,
   *  waitForOperation, etc.). */
  nodeClient(): CertcryptNodeClient {
    return this.client;
  }
}
