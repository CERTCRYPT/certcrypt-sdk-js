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

// CERTCRYPT SDK for JavaScript — public surface.
//
// What is deliberately NOT exported: single signature components (an ML-DSA-65
// or a P-256 signer, keygen or verifier on its own). A composite is valid only
// as the AND of both, so exposing one half would hand out a way to produce
// something that looks like a signature and carries no post-quantum half.

export {
  CertcryptNodeClient,
  CertcryptNodeError,
  type NodeClientOptions,
  type WaitOptions,
  // Reported to `WaitOptions.onProgress` on every poll tick: an integrator that
  // types its callback needs this, and without it the only option is `any`.
  type WaitProgress,
  type VerificationPackage,
  type BuildPackageOptions,
  type DeadLetter,
  type RetryOptions,
  // What `CertcryptNodeClient.activate()` returns.
  type ActivationResult,
} from "./client.js";
// The transport-retry policy in `retry.ts`, exported
// so an integrator wrapping its own transport can apply the same decisions.
export {
  decideRetry,
  parseRetryAfter,
  RETRY_DEFAULTS,
  RETRY_AFTER_MIN_MS,
  RETRY_AFTER_MAX_MS,
  type RetryPolicy,
  type RetryDecision,
  type TransportOutcome,
} from "./retry.js";
export {
  buildCommitmentInclusionProof,
  commitmentLeafHash,
  commitmentSubtreeRoot,
  COMMITMENT_LEAF_VERSION,
  type CommitmentInclusionProof,
} from "./artifacts/commitment-inclusion.js";
export type {
  LooseCommitment,
  IssueRequest,
  IssueResponse,
  OperationRecord,
  OperationState,
  // One per-member result of an issue response; `commitment_index` correlates it
  // back to the request.
  MemberResult,
  // The node's settlement-window estimate, surfaced on a pending resolution and
  // on each progress tick. Public because callers schedule on `expected_settled_by`
  // and `target_close_by`.
  SettlementWindowEstimate,
  // The type of `WaitProgress.settlement`. Exported for the same reason
  // `WaitProgress` itself is: a caller that branches on `queued` vs
  // `finality_pending` cannot name the field's type without it.
  SettlementProgress,
  // Recovery: what an integration still has open. `truncated` MUST be checked —
  // a truncated page read as complete becomes a re-emission.
  UnresolvedEmission,
  UnresolvedEmissions,
} from "./types.js";

// RFC 3339 second-precision timestamp normalization (shared by the zero-data
// evidence path).
export { toRfc3339Seconds } from "./artifacts/rfc3339.js";
export {
  buildAiDecisionPart,
  buildAiDecisionSubject,
  type AiDecisionMaterialInput,
  type AiDecisionPartDescriptor,
  type BuiltAiDecisionPart,
  type AiDecisionModel,
  type BuildAiDecisionSubjectInput,
  type AiDecisionRecord,
  type AiDecisionMaterialRecord,
  type BuiltAiDecisionSubject,
} from "./crypto/ai-decision.js";
// The SDK exposes the EVIDENCE producer (what only the holder can do — sign a
// projected commitment). It exposes no submission-set builder: the node is the
// builder.
export {
  assembleEvidence,
  evidenceDigestHex,
  projectedCommitmentSigningBytes,
  ZERO_DATA_PROFILE,
  type CapacityEvidence,
  type EvidenceInputs,
  type StableIdentifiers,
  type SignedLevel1Binding,
  type CompositeSignatureWire,
  type ComponentSignature,
  type Level1AuthorizationBinding,
  type ProjectedCommitment,
  type ProjectedAuthorization,
  type OperativeContext,
  MAX_SUBMISSION_SET_MEMBERS,
  SubmissionSetTooLargeError,
  assertSubmissionSetWithinBound,
} from "./artifacts/capacity-evidence.js";
// Verifiable-subject issuance (CCSP/1 Issued plane): the issuer builds and SIGNS
// the base_certificate with its own composite issuer key, client-side — no
// custody. Its subject anchor (CCCP/1) lets a third party verify the
// certificate against the original material offline with the verifier toolkit.
export {
  assembleBaseCertificate,
  assembleUnsignedPayload,
  computeSubjectCommitment,
  computeAnchorCommitment,
  subjectLocalDigestHex,
  payloadCanonDigestHex,
  generateNonceHex,
  generateIssuerKey,
  // The issuer's composite signing key from its seed alone; the id is a label
  // (conformance family `issuer-key-derivation`).
  deriveIssuerKey,
  // expires_at = issued_at + the rules domain's commitment TTL.
  computeExpiresAt,
  // Collection subjects declared by leaves, resolved under the anchor nonce.
  resolveCollectionSubjects,
  // CCVP/1: a context snapshot certificate, and the composite key fingerprint
  // its entries and a certificate's declared context name.
  assembleContextSnapshotCertificate,
  issuerKeyFingerprintHex,
  type ConsistencyContext,
  type AssembleContextSnapshotInput,
  type ResolvedCollection,
  type SubjectInput,
  type IssuanceTarget,
  type SubjectCommitment,
  type CertificateAnchor,
  type CertificatePayload,
  type CertificateSignature,
  type BaseCertificate,
  type MintedCertificate,
  type IssuerKey,
  type AssemblePayloadInput,
  type AssembleBaseCertificateInput,
} from "./artifacts/base-certificate.js";
export {
  canonicalBytesForSubject,
  UnsupportedProfileError,
  SUBJECT_BINARY,
  SUBJECT_TEXT,
  SUBJECT_EMAIL,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
  SUBJECT_CONTEXT_SNAPSHOT,
  SUPPORTED_SUBJECT_PROFILES,
} from "./crypto/canonical-subject.js";
// The precondition failure the JSON-object profiles raise. Exported alongside the
// other typed errors so an integrator can distinguish "my subject is malformed"
// (fix the input) from a transport or node failure (retry) — catching it by
// message text would be the only alternative.
export { SubjectPreconditionError } from "./crypto/subject-json-preconditions.js";
// `subject.collection/1` Merkle primitives. Exported because building an
// ELEMENT-LEVEL inclusion proof is an ISSUER-side job — only whoever holds the
// certificate has the collection's leaf digests — and folding the path by hand is
// the one place an integrator reliably gets it wrong: a lone right-edge node on an
// odd level is promoted unchanged and contributes NO sibling. `collectionInclusionProof`
// already implements that (and the conformance vectors cover odd cardinalities), so
// an issuer never has to reimplement it, nor pull in the verifier toolkit to emit.
export {
  collectionLeafHash,
  collectionNodeHash,
  collectionMerkleRoot,
  collectionInclusionProof,
  buildCollection,
  COLLECTION_MERKLE_SCHEME,
  type CollectionLeafInput,
  type BuiltCollection,
} from "./crypto/collection-merkle.js";
// SHA3-256 and RFC 8785 (JCS): the two byte primitives every digest in the
// protocol is built from, exported so an integrator recomputes a digest with the
// exact bytes this SDK signs rather than an approximation.
export { digestBytes, digestHexBytes, digestHexText } from "./crypto/digest.js";
export { jcsCanonicalizeBytes, jcsCanonicalizeString } from "./crypto/jcs.js";
export {
  compositeSignP256,
  compositeMPrime,
  PROFILE_P256_MLDSA65,
} from "./crypto/composite.js";
// The holder's operation-key tree. A first-party issuer builds one (e.g. from a
// custodied seed), commits its root in the Level-1 authorization, and signs each
// zero-data commitment with a distinct, never-reused leaf.
export {
  HolderKeySet,
  type OperationKey,
  type OperationKeyDisclosure,
} from "./artifacts/holder-keyset.js";
export {
  Certcrypt,
  InMemoryLeafStore,
  // Rebuilds a handle from a recovered fragment + the issuer-held certificate.
  // Refuses a fragment whose emission has not settled rather than inventing a
  // Merkle position.
  emissionHandleFromRecovery,
} from "./issuer.js";
export type {
  CertcryptOptions,
  IssueInput,
  IssueResult,
  // Grouping: one certificate signed but not yet sent, and what submitting a
  // batch of them returns. Grouping N into one set amortizes the per-submission
  // overhead across all of them.
  PreparedCommitment,
  SubmitResult,
  IssuerMode,
  // The issuer-elected settlement window `issue()` and `submit()` accept.
  SettlementPreferences,
  LeafStore,
  BindingStore,
  BindingStoreEntry,
  EmissionHandle,
  EmissionResolution,
  // Recovery: the half CERTCRYPT can return, and the join that rebuilds a handle
  // from it plus the issuer-held certificate.
  RecoveredHandleFragment,
} from "./issuer.js";

// The rules domains this SDK implements. Emitting under any other is refused
// at construction — see rules-domain/1 §14.2.
export { SUPPORTED_RULES_VERSIONS, registerRulesDomain } from "./issuer.js";
