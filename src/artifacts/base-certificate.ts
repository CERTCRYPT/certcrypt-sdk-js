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
 * Issuer-side minter of the CCSP/1 `base_certificate` with a verifiable subject
 * anchor — the object the verifier's Issued plane validates.
 *
 * NO CUSTODY: the issuer builds and SIGNS the `base_certificate` with its own
 * issuer key, client-side. CERTCRYPT never holds the key and never signs on the
 * issuer's behalf. This module builds the anchor + payload (CCCP/1
 * per-subject and anchor commitments) and, given a signer, produces the
 * signed certificate and its `certificate_commitment_digest = SHA3(JCS(cert))`.
 *
 * Byte parity is load-bearing and pinned by the conformance vectors — both the
 * per-subject commitments and whole certificates.
 * A one-byte divergence in the anchor JCS, the per-subject and anchor concatenation, or the
 * payload JCS breaks verification cross-language.
 */

import { createHash, randomBytes, type KeyObject } from "node:crypto";
import { digestHexText, digestHexBytes } from "../crypto/digest.js";
import { jcsCanonicalizeString, jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { canonicalBytesForSubject } from "../crypto/canonical-subject.js";
import { buildCollection, type CollectionLeafInput } from "../crypto/collection-merkle.js";
import {
  compositeSignP256,
  type CompositeSignatureWire,
} from "../crypto/composite.js";
import {
  generateEcdsaP256KeyPair,
  privateKeyFromScalar,
  scalarFromSeedMaterial,
  publicKeyB64FromPrivate,
} from "../crypto/ecdsa-p256.js";
import { keygenMlDsa65 } from "../crypto/ml-dsa.js";
import { toRfc3339Seconds } from "./rfc3339.js";

const HEX64_RE = /^[0-9a-f]{64}$/;
const CERTIFICATE_SCHEMA = "certcrypt-certificate";

/** One certified subject as it appears in `payload.anchor.subjects[]` (CCSP/1). */
export interface SubjectCommitment {
  profile: string;
  commitment_digest_hex: string;
  /**
   * `subject.collection/1` only: the signed collection descriptor. CCSP/1 §7.3.2 allows
   * additional members whose meaning a referenced normative spec defines, and this is
   * that case — the descriptor rides INSIDE the subject so each leaf's profile enters
   * the signature (the profile decides how the leaf canonicalizes, so an unsigned one
   * would be forgeable).
   */
  collection?: CollectionDescriptor;
}

/** The signed `subject.collection/1` descriptor (four members, `subject.collection/1` §7). */
export interface CollectionDescriptor {
  commitment_scheme: string;
  root: string;
  declared_cardinality: string;
  leaves: { profile: string; commitment_digest_hex: string }[];
}

/** The signed issuance-time root (CCSP/1). A closed object. */
export interface CertificateAnchor {
  issued_at: string;
  nonce_hex: string;
  root_id?: string;
  subjects: SubjectCommitment[];
}

/** The normative payload (CCSP/1). `anchor_commitment_digest_hex` is a sibling of `anchor`. */
export interface CertificatePayload {
  anchor: CertificateAnchor;
  anchor_commitment_digest_hex: string;
  system_id: string;
  rules_version: string;
  /** The declared context this certificate names for CCVP/1 (CCVP/1 §5.2). */
  context?: ConsistencyContext;
  /** The snapshot a context snapshot certificate carries (CCVP/1 §6). */
  snapshot?: Record<string, unknown>;
}

/**
 * The declared context a certificate names for CCVP/1 consistency (CCVP/1
 * §5.2): the snapshot issuer by label AND composite key fingerprint, and the
 * context set. Naming the key is what keeps anyone else from publishing
 * snapshots in this namespace under the same label.
 */
export interface ConsistencyContext {
  snapshot_issuer_id: string;
  /** `issuerKeyFingerprintHex(snapshotIssuerKey)`. */
  snapshot_issuer_fingerprint_digest_hex: string;
  context_set_id: string;
}

/** One subject the issuer wants to certify: its declared profile + raw material bytes. */
export interface SubjectInput {
  /** e.g. "subject.binary/1", "subject.text/1". The profile string, byte-compared. */
  profile: string;
  /**
   * The subject's ORIGINAL bytes. For JSON-object profiles
   * (subject.collection/1, subject.ai-decision/1) these are the JSON source
   * bytes; the VALUE is re-canonicalized. `canonicalBytesForSubject` handles the
   * per-profile transform.
   *
   * For a `subject.collection/1` declared via `leaves`, omit this: the SDK builds
   * the descriptor itself and fills it in.
   */
  material?: Uint8Array;
  /**
   * A `subject.collection/1` declared by its ORDERED leaf materials instead of a
   * prebuilt descriptor.
   *
   * Preferred for collections. The root is salted with the certificate's anchor
   * `nonce_hex` (`subject.collection/1` §8), which does not exist until `issue()`
   * generates it — so a caller CANNOT compute a correct root beforehand. Supplying
   * leaves lets the SDK build the descriptor at the right moment and return the
   * leaf hashes the issuer needs to build inclusion proofs.
   *
   * Each leaf declares its OWN profile, so one collection may mix texts, binaries and
   * emails (`subject.collection/1` §7.4).
   */
  leaves?: CollectionLeafInput[];
  /** Set by `resolveCollectionSubjects`; callers do not supply this. */
  collection?: CollectionDescriptor;
}

export interface AssemblePayloadInput {
  subjects: SubjectInput[];
  /** 64 lowercase hex, one nonce per anchor (CSPRNG, non-reuse). `generateNonceHex()`. */
  nonce_hex: string;
  /** RFC 3339 UTC with 'Z'. */
  issued_at: string;
  /** Optional; when present, the system_root_fingerprint (64 lowercase hex). */
  root_id?: string;
  system_id: string;
  rules_version: string;
  /**
   * Optional CCVP/1 declared context, signed with the payload. Opting in only
   * lets a verifier evaluate consistency; it never changes Issued or
   * Independent.
   */
  context?: ConsistencyContext;
}

/**
 * CCCP/1 per-subject commitment:
 *   commitment_digest_hex = SHA3-256(ASCII(nonce_hex) || ASCII(subject_local_digest_hex))
 * where subject_local_digest_hex = SHA3-256(canonical_bytes). The hex
 * strings are concatenated as ASCII bytes and NOT decoded first (the most common
 * cross-language error). `digestHexText` hashes the UTF-8/ASCII bytes of the
 * string, which is exactly this.
 */
export function computeSubjectCommitment(
  nonce_hex: string,
  subjectLocalDigestHex: string
): string {
  return digestHexText(nonce_hex + subjectLocalDigestHex);
}

/** `subject_local_digest_hex = SHA3-256(canonical_bytes(subject))` (CCCP/1). */
export function subjectLocalDigestHex(subject: SubjectInput): string {
  if (subject.material === undefined) {
    throw new Error(
      `subject of profile ${subject.profile} has no material: a collection declared via ` +
        `\`leaves\` must be resolved with resolveCollectionSubjects() first`
    );
  }
  return digestHexBytes(canonicalBytesForSubject(subject.profile, subject.material));
}

/** What `resolveCollectionSubjects` produced for one collection subject. */
export interface ResolvedCollection {
  /** Zero-based index of the subject in `anchor.subjects[]`. */
  subjectIndex: number;
  descriptor: CollectionDescriptor;
  /**
   * Leaf hashes in leaf order. They travel signed inside the descriptor; the
   * issuer also keeps them locally to build inclusion proofs.
   */
  leafHashes: string[];
}

/**
 * Turn every `leaves`-declared collection subject into a concrete descriptor,
 * salted with this certificate's nonce.
 *
 * Returns the resolved subjects plus, per collection, the descriptor and leaf hashes.
 * Both ship signed inside the certificate and are readable from there, ordered — so an
 * inclusion proof can be rebuilt from the certificate alone. What the certificate does
 * NOT carry is the leaf MATERIAL: each leaf is a salted digest, and no party can
 * recover the bytes behind it. Proving a member still requires holding that member.
 */
export function resolveCollectionSubjects(
  subjects: SubjectInput[],
  nonceHex: string
): { subjects: SubjectInput[]; collections: ResolvedCollection[] } {
  const salt = new TextEncoder().encode(nonceHex);
  const collections: ResolvedCollection[] = [];
  const resolved = subjects.map((s, i) => {
    if (!s.leaves) return s;
    if (s.material !== undefined) {
      throw new Error(
        `subject ${i}: pass either \`material\` or \`leaves\`, not both`
      );
    }
    const built = buildCollection(salt, s.leaves);
    collections.push({
      subjectIndex: i,
      descriptor: built.descriptor,
      leafHashes: built.leafHashes,
    });
    // The descriptor is the subject's material AND rides in the subject object itself:
    // the same bytes serve as what the commitment digests and as what the verifier
    // reads without needing a delivered file.
    return {
      profile: s.profile,
      material: jcsCanonicalizeBytes(built.descriptor),
      collection: built.descriptor,
    };
  });
  return { subjects: resolved, collections };
}

/**
 * CCCP/1 anchor commitment:
 *   anchor_commitment_digest_hex =
 *     SHA3-256(ASCII(nonce_hex) || ASCII(SHA3-256(RFC8785(anchor))))
 * Published in `payload.anchor_commitment_digest_hex`.
 */
export function computeAnchorCommitment(anchor: CertificateAnchor): string {
  const anchorCanonHex = digestHexBytes(jcsCanonicalizeBytes(anchor));
  return digestHexText(anchor.nonce_hex + anchorCanonHex);
}

/** 256-bit CSPRNG nonce as 64 lowercase hex chars. Non-reuse is the caller's invariant. */
export function generateNonceHex(): string {
  return Buffer.from(randomBytes(32)).toString("hex");
}

/**
 * Derive the evidence `expires_at = issued_at + ttl` (capacity.commitment/1),
 * keeping RFC 3339 second precision (byte-parity with the canonical bytes).
 *
 * The TTL is NOT chosen here: it comes from the active rules-domain registry, and
 * the value it yields is the signed settlement-bound deadline a verifier evaluates
 * under the dual temporal condition. This function takes it as a parameter — a
 * wrong value fails verification closed.
 *
 * `issued_at` MUST be RFC 3339 UTC second precision (…Z); `ttl_seconds` MUST be a
 * positive whole number of seconds.
 */
export function computeExpiresAt(issued_at: string, ttl_seconds: number): string {
  const normalizedIssued = toRfc3339Seconds(issued_at);
  if (!Number.isInteger(ttl_seconds) || ttl_seconds <= 0) {
    throw new Error(
      `ttl_seconds must be a positive whole number of seconds (got ${ttl_seconds})`
    );
  }
  const expires = new Date(Date.parse(normalizedIssued) + ttl_seconds * 1000);
  return toRfc3339Seconds(expires);
}

/**
 * Build the unsigned CCSP/1 payload with a verifiable subject anchor. Computes
 * each subject's commitment from its material (subject_local_digest never
 * leaves this process), assembles the anchor, and computes the anchor
 * commitment. The subject order is preserved (CCSP/1 — order is
 * significant and the normative subject count).
 *
 * Throws on a malformed nonce or an empty subject set (fail-fast; the verifier
 * would reject these downstream).
 */
export function assembleUnsignedPayload(input: AssemblePayloadInput): CertificatePayload {
  if (!HEX64_RE.test(input.nonce_hex)) {
    throw new Error(
      `nonce_hex must be 64 lowercase hex chars (got ${JSON.stringify(input.nonce_hex)})`
    );
  }
  if (input.subjects.length === 0) {
    throw new Error("at least one subject is required (CCSP/1)");
  }
  if (input.root_id !== undefined && !HEX64_RE.test(input.root_id)) {
    throw new Error(
      `root_id must be 64 lowercase hex chars when present (got ${JSON.stringify(input.root_id)})`
    );
  }

  if (input.context !== undefined) assertConsistencyContext(input.context);

  const subjects: SubjectCommitment[] = input.subjects.map((s) => ({
    profile: s.profile,
    commitment_digest_hex: computeSubjectCommitment(
      input.nonce_hex,
      subjectLocalDigestHex(s)
    ),
    ...(s.collection !== undefined ? { collection: s.collection } : {}),
  }));

  const anchor: CertificateAnchor = {
    issued_at: input.issued_at,
    nonce_hex: input.nonce_hex,
    ...(input.root_id !== undefined ? { root_id: input.root_id } : {}),
    subjects,
  };

  return {
    anchor,
    anchor_commitment_digest_hex: computeAnchorCommitment(anchor),
    system_id: input.system_id,
    rules_version: input.rules_version,
    ...(input.context !== undefined ? { context: { ...input.context } } : {}),
  };
}

function assertConsistencyContext(ctx: ConsistencyContext): void {
  if (typeof ctx.snapshot_issuer_id !== "string") {
    throw new Error("context.snapshot_issuer_id must be a string (CCVP/1 §5.2)");
  }
  if (!HEX64_RE.test(ctx.snapshot_issuer_fingerprint_digest_hex)) {
    throw new Error(
      "context.snapshot_issuer_fingerprint_digest_hex must be 64 lowercase hex chars (CCVP/1 §5.2)"
    );
  }
  if (typeof ctx.context_set_id !== "string" || ctx.context_set_id.length === 0) {
    throw new Error("context.context_set_id must be a non-empty string (CCVP/1 §5.2)");
  }
}

/** `payload_canon_digest_hex = SHA3-256(RFC8785(payload))`, lowercase hex. */
export function payloadCanonDigestHex(payload: CertificatePayload): string {
  return digestHexText(jcsCanonicalizeString(payload));
}

/**
 * Explicit issuance-target choice, closing the silent fail-open where an absent
 * `root_id` quietly produces a certificate that can NEVER reach `Independent`.
 *
 * - `issued-only`: the issuer consciously emits a certificate that is
 *   Issued-valid but NOT eligible for `Independent` (no participation reference).
 *   Verifiable against original material offline; simply never anchored.
 * - `independent-capable`: the certificate targets `Independent`. REQUIRES
 *   `root_id` (= the domain's `system_root_fingerprint`), the signed
 *   issuance-time participation reference (CCSP/1; independence.proof/1).
 *   Without it, no later step can make the certificate Independent — a
 *   non-repairable emission choice, so it must be explicit, never a defaulted
 *   omission.
 *
 * NOTE: `root_id` is OPTIONAL at the CCSP/1 layer — an Issued-only certificate is
 * legitimate. This discriminated choice does not make it mandatory; it makes the
 * choice deliberate.
 */
export type IssuanceTarget =
  | { mode: "issued-only" }
  | { mode: "independent-capable"; root_id: string };

/**
 * The issuer's composite signing identity (client-side custody). The
 * private components never leave the issuer process; only the public keys +
 * `signer.id` travel in the certificate. Obtain one whole from
 * `generateIssuerKey` / `deriveIssuerKey`. `p256Private` is a node KeyObject;
 * `mldsaSecret` is the raw ML-DSA-65 secret. `pub_p256_b64` is SEC1 uncompressed
 * (65B) base64; `pub_mldsa_b64` is the raw ML-DSA-65 public key base64.
 */
export interface IssuerKey {
  id: string;
  p256Private: KeyObject;
  mldsaSecret: Uint8Array;
  pub_p256_b64: string;
  pub_mldsa_b64: string;
}

/** One `signatures[]` entry of the base certificate (composite issuer). */
export interface CertificateSignature {
  role: string;
  sig_target: string;
  alg: string;
  mode: string;
  signatures: CompositeSignatureWire["signatures"];
  signer: {
    id: string;
    pub_p256_b64: string;
    pub_mldsa_b64: string;
  };
}

/** The signed CCSP/1 base certificate. */
export interface BaseCertificate {
  schema: string;
  payload: CertificatePayload;
  payload_canon_digest_hex: string;
  signatures: CertificateSignature[];
}

/** The minter's output: the signed cert plus its LEAF-BINDING digest. */
export interface MintedCertificate {
  base_certificate: BaseCertificate;
  /** `certificate_commitment_digest = SHA3(JCS(base_certificate))` (LEAF-BINDING). */
  certificate_commitment_digest: string;
}

export interface AssembleBaseCertificateInput extends AssemblePayloadInput {
  issuerKey: IssuerKey;
}

/**
 * Generate a fresh, random issuer composite key (P-256 + ML-DSA-65) for
 * development and tests. Issuance derives the key from the seed
 * (`deriveIssuerKey`) or takes an injected one (e.g. KMS-backed); a random key
 * cannot be re-derived from the seed, so do NOT use this to mint production
 * certificates.
 */
export function generateIssuerKey(id: string): IssuerKey {
  const p256 = generateEcdsaP256KeyPair();
  const mldsa = keygenMlDsa65();
  return {
    id,
    p256Private: p256.privateKey,
    mldsaSecret: mldsa.secretKey,
    pub_p256_b64: p256.publicKeyB64,
    pub_mldsa_b64: Buffer.from(mldsa.publicKey).toString("base64"),
  };
}

/**
 * Derive the issuer's composite signing key DETERMINISTICALLY from the same
 * 32-byte master seed the SDK already holds (the one `HolderKeySet.fromMasterSeed`
 * uses for the operation-key tree). The issuer therefore provisions ONE secret —
 * the seed it supplies — and the SDK derives from it:
 *   - the operation-key tree (signs capacity evidence), via `op-key/<i>`, and
 *   - THIS composite cert-signing key, via a DISTINCT domain label.
 *
 * The two derivations are domain-separated (different SHA3 labels) so the cert key
 * is cryptographically independent of the operation keys — a design invariant, not
 * a convenience. The issuer NEVER handles this key; it is reconstructed from the
 * seed each run, so it is stable across restarts (same seed → same issuer identity)
 * with no stored key material and no KMS in the "first certificate" path.
 *
 * Self-contained: the public halves are carried inside every base_certificate, so
 * a verifier reaches INDEPENDENT_VALID without any registry lookup.
 *
 * (A KMS-backed IssuerKey can be injected instead of deriving — a deliberate
 * hardening, not a requirement for issuance.)
 *
 * @param masterSeed 32-byte seed (Uint8Array or 64-hex string), same as the keyset.
 * @param id         the issuer key id stamped into the certificate's signer block.
 */
export function deriveIssuerKey(masterSeed: Uint8Array | string, id: string): IssuerKey {
  const seed =
    typeof masterSeed === "string" ? Buffer.from(masterSeed, "hex") : Buffer.from(masterSeed);
  if (seed.length !== 32) {
    throw new Error("issuer key master seed must be 32 bytes (64 hex chars)");
  }
  // Domain-separated derivations (distinct labels → independent of op-key/<i>).
  const p256Material = createHash("sha3-256")
    .update(seed)
    .update(Buffer.from("issuer-cert-key/p256", "utf8"))
    .digest();
  const mldsaSeed = createHash("sha3-256")
    .update(seed)
    .update(Buffer.from("issuer-cert-key/mldsa", "utf8"))
    .digest();

  const p256Private = privateKeyFromScalar(scalarFromSeedMaterial(p256Material));
  const mldsa = keygenMlDsa65(mldsaSeed);
  return {
    id,
    p256Private,
    mldsaSecret: mldsa.secretKey,
    pub_p256_b64: publicKeyB64FromPrivate(p256Private),
    pub_mldsa_b64: Buffer.from(mldsa.publicKey).toString("base64"),
  };
}

/**
 * Mint a signed CCSP/1 base certificate with a verifiable subject anchor
 * (the issuer signs client-side). Builds the payload, composite-signs
 * `payload_canon_digest_hex` with the issuer key, and returns the
 * certificate plus `certificate_commitment_digest = SHA3(JCS(cert))`.
 *
 * The result verifies under the toolkit's Issued plane (structure → composite
 * issuer signature → original-material).
 */
export function assembleBaseCertificate(
  input: AssembleBaseCertificateInput
): MintedCertificate {
  return signPayload(assembleUnsignedPayload(input), input.issuerKey);
}

/** Composite-sign a finished payload into a CCSP/1 base certificate. */
function signPayload(payload: CertificatePayload, issuerKey: IssuerKey): MintedCertificate {
  const canonDigest = payloadCanonDigestHex(payload);

  const composite = compositeSignP256(canonDigest, {
    p256Private: issuerKey.p256Private,
    mldsaSecret: issuerKey.mldsaSecret,
  });

  const signature: CertificateSignature = {
    role: "issuer",
    sig_target: "payload_canon_digest_hex",
    alg: composite.alg,
    mode: composite.mode,
    signatures: composite.signatures,
    signer: {
      id: issuerKey.id,
      pub_p256_b64: issuerKey.pub_p256_b64,
      pub_mldsa_b64: issuerKey.pub_mldsa_b64,
    },
  };

  const base_certificate: BaseCertificate = {
    schema: CERTIFICATE_SCHEMA,
    payload,
    payload_canon_digest_hex: canonDigest,
    signatures: [signature],
  };

  return {
    base_certificate,
    certificate_commitment_digest: digestHexText(
      jcsCanonicalizeString(base_certificate)
    ),
  };
}

/**
 * The composite key fingerprint of an issuer key (CCVP/1 §8.1):
 * `SHA3-256(pub_p256_bytes || pub_mldsa_bytes)` over the decoded keys, classical
 * first — the construction of composite-signature/1 §10. It is the value a
 * context snapshot entry names in `pub_fingerprint_digest_hex`, and the value a
 * certificate names in `context.snapshot_issuer_fingerprint_digest_hex` for the
 * key that signs its snapshots.
 */
export function issuerKeyFingerprintHex(
  key: Pick<IssuerKey, "pub_p256_b64" | "pub_mldsa_b64">
): string {
  return digestHexBytes(
    Buffer.concat([
      Buffer.from(key.pub_p256_b64, "base64"),
      Buffer.from(key.pub_mldsa_b64, "base64"),
    ])
  );
}

export interface AssembleContextSnapshotInput {
  /**
   * The snapshot object (CCVP/1 §6): `context_set_id`, `snapshot_id`,
   * `issued_at` (its effective time) and `entries`, plus optional members such
   * as `policy_refs`. It is carried as `payload.snapshot` exactly as given, so
   * fix array order and timestamp spelling before calling.
   */
  snapshot: Record<string, unknown>;
  issuerKey: IssuerKey;
  /** 64 lowercase hex. `generateNonceHex()`. */
  nonce_hex: string;
  /** The certificate's own issuance time, RFC 3339 UTC with 'Z'. */
  issued_at: string;
  system_id: string;
  rules_version: string;
}

/** CCSP/1 §7.3.1 form, which CCVP/1 §6.3 adopts for every timestamp. */
const CCVP_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/;

function assertSnapshotShape(snapshot: Record<string, unknown>): void {
  const fail = (what: string): never => {
    throw new Error(`context snapshot: ${what} (CCVP/1 §6, §7.1)`);
  };
  if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) {
    fail("the snapshot must be a JSON object");
  }
  for (const k of ["context_set_id", "snapshot_id"]) {
    const v = snapshot[k];
    if (typeof v !== "string" || v.length === 0) fail(`${k} must be a non-empty string`);
  }
  const ts = (v: unknown) => typeof v === "string" && CCVP_TIMESTAMP_RE.test(v);
  if (!ts(snapshot.issued_at)) fail("issued_at must be an RFC 3339 UTC timestamp ending in Z");
  if (!Array.isArray(snapshot.entries)) fail("entries must be an array");
  (snapshot.entries as unknown[]).forEach((e, i) => {
    if (typeof e !== "object" || e === null || Array.isArray(e)) fail(`entries[${i}] must be an object`);
    const entry = e as Record<string, unknown>;
    if (typeof entry.issuer_id !== "string" || entry.issuer_id.length === 0) {
      fail(`entries[${i}].issuer_id must be a non-empty string`);
    }
    if (typeof entry.pub_fingerprint_digest_hex !== "string" || !HEX64_RE.test(entry.pub_fingerprint_digest_hex)) {
      fail(`entries[${i}].pub_fingerprint_digest_hex must be 64 lowercase hex chars`);
    }
    if (typeof entry.status !== "string") fail(`entries[${i}].status must be a string`);
    if (!ts(entry.valid_from)) fail(`entries[${i}].valid_from must be an RFC 3339 UTC timestamp`);
    for (const k of ["valid_to", "revoked_at"]) {
      if (k in entry && entry[k] !== null && !ts(entry[k])) {
        fail(`entries[${i}].${k} must be null or an RFC 3339 UTC timestamp`);
      }
    }
  });
}

/**
 * Mint a CCVP/1 context snapshot certificate: a CCSP/1 certificate carrying
 * `snapshot` as `payload.snapshot` and exactly one `subject.context-snapshot/1`
 * subject committing to it (CCVP/1 §5.1). The snapshot issuer is the key that
 * signs it; verifiers derive it from the signature, never from the snapshot.
 *
 * The snapshot is checked against the CCVP/1 shape and the profile's own
 * preconditions (no JSON number at any depth) before anything is signed. It is
 * an ordinary Issued certificate, with no root participation reference.
 */
export function assembleContextSnapshotCertificate(
  input: AssembleContextSnapshotInput
): MintedCertificate {
  assertSnapshotShape(input.snapshot);
  const payload = assembleUnsignedPayload({
    subjects: [
      {
        profile: "subject.context-snapshot/1",
        material: new TextEncoder().encode(JSON.stringify(input.snapshot)),
      },
    ],
    nonce_hex: input.nonce_hex,
    issued_at: input.issued_at,
    system_id: input.system_id,
    rules_version: input.rules_version,
  });
  payload.snapshot = structuredClone(input.snapshot);
  return signPayload(payload, input.issuerKey);
}
