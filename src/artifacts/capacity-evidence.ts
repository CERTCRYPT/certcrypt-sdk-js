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
 * Issuer-side assembly of zero-data `capacity.evidence/1` — the projected,
 * unlinkable view of a `capacity.commitment/1`: stable identifiers become
 * operation-scoped pseudonyms, and the holder signs with a non-reused
 * per-operation leaf key proven to belong to the authorized `holder_key_set_root`.
 *
 * DIVISION OF SIGNING LABOR: the Level-1 binding and its signature are NOT
 * produced here. They are minted during activation and handed to the issuer, who
 * passes them in verbatim — the key that signs them never exists in the SDK. The
 * SDK signs ONLY the Level-3 projected commitment, with the leaf key it does hold.
 *
 * BYTE PARITY IS LOAD-BEARING: the projected commitment's signing bytes are its
 * fields in DECLARATION order (insertion order, NOT JCS). Every implementation
 * must agree exactly; it is pinned by the conformance vectors.
 */

import { Buffer } from "node:buffer";
import { jcsCanonicalizeString } from "../crypto/jcs.js";
import { digestHexText } from "../crypto/digest.js";
import { toRfc3339Seconds } from "./rfc3339.js";
import { derivePseudonym } from "../crypto/pseudonym.js";
import { HolderKeySet, type OperationKeyDisclosure } from "./holder-keyset.js";

/**
 * The exact Level-1 binding the system-domain signed, with its signature.
 * Produced during activation and passed in
 * verbatim — the SDK never recomputes or re-signs it. Field order is the
 * signing-bytes order and is load-bearing.
 */
export interface Level1AuthorizationBinding {
  system_id: string;
  rules_version: string;
  system_root_fingerprint: string;
  authorized_role: string;
  authorization_issuer_kid: string;
  valid_from: string;
  valid_until: string;
  holder_key_set_root: string;
}

/** One detached component signature of a composite. `encoding`/`low_s` are
 *  present only for ECDSA; omitted for ML-DSA/Ed25519. */
export interface ComponentSignature {
  alg: string;
  encoding?: string;
  low_s?: boolean;
  sig_b64: string;
}

/** The Level-1 signature as it appears on the wire: a PQ/T COMPOSITE,
 *  AND over all components. The SDK
 *  carries it VERBATIM from activation into the projected
 *  authorization — it never re-signs or reshapes it (the exact bytes/field order
 *  are load-bearing for the verifier's composite check). */
export interface CompositeSignatureWire {
  alg: string;
  mode: string;
  signatures: ComponentSignature[];
}

/** The pre-signed Level-1 anchor handed to the issuer at activation.
 *  The signature is a PQ/T composite carried verbatim. */
export interface SignedLevel1Binding {
  level1_binding: Level1AuthorizationBinding;
  level1_signature: CompositeSignatureWire;
}

export interface ProjectedCommitment {
  commitment_version: string;
  system_id: string;
  system_root_fingerprint: string;
  rules_version: string;
  authorization_pseudonym: string;
  holder_pseudonym: string;
  pool_pseudonym: string;
  certificate_commitment_digest: string;
  consumed_quantity: string;
  /**
   * Issuer-declared per-subject effective units (`submission-set/1`):
   * non-collection subject → "1", collection → its `declared_cardinality`.
   * Distinct from `consumed_quantity`, and part of the signed view.
   */
  declared_effective_units: string;
  issued_at: string;
  expires_at: string;
}

export interface ProjectedAuthorization {
  system_id: string;
  rules_version: string;
  system_root_fingerprint: string;
  authorized_role: string;
  authorization_issuer_kid: string;
  valid_from: string;
  valid_until: string;
  holder_key_set_root: string;
  level1_binding: Level1AuthorizationBinding;
  level1_signature: CompositeSignatureWire;
  authorization_pseudonym: string;
  holder_pseudonym: string;
}

export interface CapacityEvidence {
  profile: string;
  operation_salt_hex: string;
  projected_authorization: ProjectedAuthorization;
  projected_commitment: ProjectedCommitment;
  operation_key: OperationKeyDisclosure;
  commitment_signature_b64: string;
}

export const ZERO_DATA_PROFILE = "zero-data.unlinkable";

/** The stable identifiers the issuer holds privately and projects to pseudonyms. */
export interface StableIdentifiers {
  holder_id: string;
  pool_id: string;
  authorization_id: string;
}

export interface EvidenceInputs {
  /** The pre-signed Level-1 anchor from activation. */
  signedLevel1: SignedLevel1Binding;
  certificate_commitment_digest: string;
  consumed_quantity: string;
  /**
   * Issuer-declared per-subject effective units (`submission-set/1`):
   * non-collection subject → "1", collection → its declared_cardinality.
   */
  declared_effective_units: string;
  issued_at: string;
  expires_at: string;
  stable: StableIdentifiers;
  /** The holder's authorized operation-key tree. Its root MUST equal the binding's. */
  keySet: HolderKeySet;
  /** Which leaf signs this commitment. MUST NOT be reused across commitments. */
  leafIndex: number;
  /** Fresh public per-operation salt. MUST be unique per operation. */
  operationSalt: Uint8Array;
}

/**
 * The bytes the per-operation leaf key signs: the projected commitment in its
 * exact declared field order (insertion order, NOT JCS).
 */
export function projectedCommitmentSigningBytes(pc: ProjectedCommitment): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(pc));
}

/**
 * The canonical evidence digest bound into `independence.proof/1`: JCS (sorted
 * keys) + SHA3-256, lowercase hex.
 */
export function evidenceDigestHex(evidence: CapacityEvidence): string {
  return digestHexText(jcsCanonicalizeString(evidence));
}

/**
 * Assemble zero-data capacity evidence for one commitment: project the
 * identifiers to operation-scoped pseudonyms, sign the projected commitment with
 * the disclosed leaf key, and carry the pre-signed Level-1 anchor verbatim.
 *
 * Throws if `keySet.root` does not equal the binding's `holder_key_set_root`
 * (the leaf membership the verifier checks would fail otherwise — fail early),
 * or if `leafIndex` is out of range.
 */
export function assembleEvidence(inputs: EvidenceInputs): CapacityEvidence {
  const { level1_binding, level1_signature } = inputs.signedLevel1;

  if (inputs.keySet.root !== level1_binding.holder_key_set_root) {
    throw new Error(
      `key set root (${inputs.keySet.root}) does not match the authorized ` +
        `holder_key_set_root (${level1_binding.holder_key_set_root})`
    );
  }

  const salt = inputs.operationSalt;
  const holderPseudonym = derivePseudonym(salt, "holder", inputs.stable.holder_id);
  const poolPseudonym = derivePseudonym(salt, "pool", inputs.stable.pool_id);
  const authorizationPseudonym = derivePseudonym(
    salt,
    "authorization",
    inputs.stable.authorization_id
  );

  const projected_commitment: ProjectedCommitment = {
    commitment_version: "capacity.commitment/1",
    system_id: level1_binding.system_id,
    system_root_fingerprint: level1_binding.system_root_fingerprint,
    rules_version: level1_binding.rules_version,
    authorization_pseudonym: authorizationPseudonym,
    holder_pseudonym: holderPseudonym,
    pool_pseudonym: poolPseudonym,
    certificate_commitment_digest: inputs.certificate_commitment_digest,
    consumed_quantity: inputs.consumed_quantity,
    declared_effective_units: inputs.declared_effective_units,
    issued_at: inputs.issued_at,
    expires_at: inputs.expires_at,
  };

  const signature = inputs.keySet.sign(
    inputs.leafIndex,
    projectedCommitmentSigningBytes(projected_commitment)
  );
  const disclosure = inputs.keySet.disclosure(inputs.leafIndex);

  const projected_authorization: ProjectedAuthorization = {
    system_id: level1_binding.system_id,
    rules_version: level1_binding.rules_version,
    system_root_fingerprint: level1_binding.system_root_fingerprint,
    authorized_role: level1_binding.authorized_role,
    authorization_issuer_kid: level1_binding.authorization_issuer_kid,
    valid_from: level1_binding.valid_from,
    valid_until: level1_binding.valid_until,
    holder_key_set_root: level1_binding.holder_key_set_root,
    level1_binding,
    level1_signature,
    authorization_pseudonym: authorizationPseudonym,
    holder_pseudonym: holderPseudonym,
  };

  return {
    profile: ZERO_DATA_PROFILE,
    operation_salt_hex: Buffer.from(salt).toString("hex"),
    projected_authorization,
    projected_commitment,
    operation_key: disclosure,
    commitment_signature_b64: Buffer.from(signature).toString("base64"),
  };
}

// ---------------------------------------------------------------------------
// Zero-data submission set: a set of `capacity.evidence/1` certificates.
//
// The zero-data form of `submission-set/1`: each certificate
// carries projected evidence (not a raw commitment), so there is no top-level
// `holder_authorizations` slice — the projected authorization travels inside
// each evidence. `operative` carries the identifiers needed to route and account
// for the operation; it is NOT part of the evidence and never reaches the offline
// verifier, which is what keeps the evidence itself zero-data.
// ---------------------------------------------------------------------------

/** Operative routing context for one certificate. Never part of the signed
 *  evidence and never surfaced to a verifier. */
export interface OperativeContext {
  holder_id: string;
  pool_id: string;
}

/** The canonical member: exactly these two fields (submission-set/1 §7.1). Both
 *  are covered by the `submission_set_id` digest. */
export interface ZeroDataSubmissionSetCertificateV1 {
  capacity_evidence: CapacityEvidence;
  operative: OperativeContext;
}

export interface ZeroDataSubmissionSetV1 {
  schema: string;
  system_id: string;
  rules_version: string;
  system_root_fingerprint: string;
  submission_set_id: string;
  closure_time: string;
  certificates: ZeroDataSubmissionSetCertificateV1[];
}

export const ZERO_DATA_SUBMISSION_SET_VERSION = "submission-set/1";

/**
 * Maximum number of members a conforming `submission-set/1` may contain
 * (submission-set/1). Normative, fail-closed protocol constant. The issuer
 * SDK runs IN the client process, so this is the fail-fast, ergonomic guard: a
 * caller who checks a count with `assertSubmissionSetWithinBound` (as the set
 * assembler, `Certcrypt.submit()` and `CertcryptNodeClient.issue()` do) gets a
 * typed error before any network call — it is not a security boundary (a client controls its own
 * process). The authoritative enforcement is the node assembler and the CERTCRYPT
 * submit endpoint, which reject an over-cardinality set fail-closed.
 *
 * The value is 64, pinned by the conformance contract
 * (`fixtures/primitives/submission-set-limits`). It keeps a set of zero-data
 * members within request sizes common transports accept (submission-set/1
 * §8.1); per-member size is independent of subject count / collection
 * cardinality.
 */
export const MAX_SUBMISSION_SET_MEMBERS = 64;

/** Thrown when a submission set would exceed `MAX_SUBMISSION_SET_MEMBERS`. */
export class SubmissionSetTooLargeError extends Error {
  readonly count: number;
  readonly max: number;
  constructor(count: number) {
    super(
      `submission set exceeds the maximum of ${MAX_SUBMISSION_SET_MEMBERS} members ` +
        `(got ${count}); the set is rejected as a whole (submission-set/1)`
    );
    this.name = "SubmissionSetTooLargeError";
    this.count = count;
    this.max = MAX_SUBMISSION_SET_MEMBERS;
  }
}

/**
 * Assert a member count is within the submission-set/1 cardinality bound.
 * Fail-fast guard for any path that builds a multi-member set — a caller that
 * groups prepared commitments, or hand-builds a `ZeroDataSubmissionSetV1`.
 * `Certcrypt.submit()` and `CertcryptNodeClient.issue()` call it before
 * sending, so an over-bound set is refused locally; the node and the submit
 * endpoint refuse one independently.
 */
export function assertSubmissionSetWithinBound(memberCount: number): void {
  if (memberCount > MAX_SUBMISSION_SET_MEMBERS) {
    throw new SubmissionSetTooLargeError(memberCount);
  }
}

export interface AssembleZeroDataSubmissionSetOptions {
  rules_version: string;
  system_root_fingerprint: string;
  /** RFC 3339 second precision 'Z'; Date is normalized (millis must be 0). */
  closure_time: Date | string;
}

/**
 * Assemble a single-certificate zero-data submission set from one assembled
 * `CapacityEvidence` and its operative context. The `submission_set_id` is
 * computed deterministically over the set without the id (JCS + SHA3).
 */
export function assembleZeroDataSubmissionSet(
  evidence: CapacityEvidence,
  operative: OperativeContext,
  opts: AssembleZeroDataSubmissionSetOptions
): ZeroDataSubmissionSetV1 {
  const closure_time = toRfc3339Seconds(opts.closure_time);
  // The canonical member: exactly `capacity_evidence` + `operative`
  // (submission-set/1 §7.1). Both are covered by the `submission_set_id` digest,
  // so the member shape and the identifier are fixed together.
  const certificates = [
    {
      capacity_evidence: evidence,
      operative,
    },
  ];
  // cardinality bound — fail-fast in-process before the id is computed.
  // (This single-certificate assembler is always within bounds; the assertion
  // makes the contract explicit at the construction point.)
  assertSubmissionSetWithinBound(certificates.length);
  // The system domain comes from the SIGNED evidence, never from a constant in this
  // SDK. The two projections carry it because the domain signed them; anything else
  // would make a conforming operator on another domain emit a set that misreports
  // its own domain — and `system_id` is covered by the `submission_set_id` digest,
  // so the id would be wrong too.
  //
  // The spec already requires `(system_id, rules_version, system_root_fingerprint)`
  // to AGREE between the two projections (anti-splicing). Enforce it here, at the
  // one point that reads it: a mismatch means the two halves came from different
  // authorizations, which must fail before anything is signed or sent.
  const commitmentSystemId = evidence.projected_commitment?.system_id;
  const authorizationSystemId = evidence.projected_authorization?.system_id;
  if (!commitmentSystemId) {
    throw new Error(
      "capacity.evidence/1 carries no projected_commitment.system_id; the submission " +
        "set's system domain is derived from the signed evidence and cannot be assumed"
    );
  }
  if (authorizationSystemId && authorizationSystemId !== commitmentSystemId) {
    throw new Error(
      `capacity.evidence/1 system_id mismatch: projected_commitment says ` +
        `"${commitmentSystemId}" but projected_authorization says ` +
        `"${authorizationSystemId}" — the two projections must agree (anti-splicing)`
    );
  }

  const withoutId = {
    schema: ZERO_DATA_SUBMISSION_SET_VERSION,
    system_id: commitmentSystemId,
    rules_version: opts.rules_version,
    system_root_fingerprint: opts.system_root_fingerprint,
    closure_time,
    certificates,
  };
  const submission_set_id = digestHexText(jcsCanonicalizeString(withoutId));
  return { ...withoutId, submission_set_id };
}
