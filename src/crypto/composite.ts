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
 * Composite signature signing (CERTCRYPT Composite Signature Profile),
 * issuer side. Signer counterpart to
 * `certcrypt-verifier-toolkit-js/core/crypto/composite.ts`.
 *
 * Every component signs the SAME domain-separated message M', and the composite
 * verifies iff ALL components verify (AND). Binding the profile id into M' stops
 * a component being lifted out and replayed under another profile.
 *
 *   M' = ASCII("CERTCRYPT-Composite-Signature-v1") || 0x00
 *        || ASCII(composite_alg_id) || 0x00 || ASCII(payload_canon_digest_hex)
 *
 * Canonical profile `certcrypt-composite-p256-mldsa65-v1`: ECDSA-P256-SHA3-256
 * (classical, FIRST — order is load-bearing) + ML-DSA-65 (PQC). The ECDSA
 * component signs SHA3-256(M') with an RFC 6979 deterministic nonce, so its bytes
 * are pinned too (`ecdsa-p256-deterministic`); ML-DSA signs M' directly, empty
 * context, no pre-hash. M' bytes are load-bearing cross-language.
 */
import { type KeyObject } from "node:crypto";
import { signEcdsaP256Raw } from "./ecdsa-p256.js";
import { signMlDsa65 } from "./ml-dsa.js";

export const COMPOSITE_DOMAIN_PREFIX = "CERTCRYPT-Composite-Signature-v1";
export const PROFILE_P256_MLDSA65 = "certcrypt-composite-p256-mldsa65-v1";
export const ALG_ECDSA_P256 = "ECDSA-P256-SHA3-256";
export const ALG_MLDSA65 = "ML-DSA-65";

/** One detached component signature (a `signatures[]` entry). */
export interface ComponentSignature {
  alg: string;
  encoding?: string;
  low_s?: boolean;
  sig_b64: string;
}

/** The composite signature wire object. */
export interface CompositeSignatureWire {
  alg: string;
  mode: string;
  signatures: ComponentSignature[];
}

/** The issuer's composite signing key (P-256 classical + ML-DSA-65 PQC). */
export interface CompositeSigningKey {
  p256Private: KeyObject;
  mldsaSecret: Uint8Array;
}

/**
 * Build the domain-separated message M' every component signs. Mirrors
 * `compositeMPrime` in the toolkit exactly.
 */
export function compositeMPrime(
  compositeAlgId: string,
  payloadCanonDigestHex: string
): Uint8Array {
  const enc = new TextEncoder();
  const prefix = enc.encode(COMPOSITE_DOMAIN_PREFIX);
  const alg = enc.encode(compositeAlgId);
  const digest = enc.encode(payloadCanonDigestHex);
  const out = new Uint8Array(prefix.length + 1 + alg.length + 1 + digest.length);
  let o = 0;
  out.set(prefix, o); o += prefix.length;
  out[o++] = 0x00;
  out.set(alg, o); o += alg.length;
  out[o++] = 0x00;
  out.set(digest, o);
  return out;
}

/**
 * Produce a composite signature over `payloadCanonDigestHex` under the canonical
 * P-256+ML-DSA-65 profile. Components are ordered classical-first (load-bearing).
 * The ECDSA component carries `encoding:"raw-rs-64"` + `low_s:true`; ML-DSA
 * carries neither.
 */
export function compositeSignP256(
  payloadCanonDigestHex: string,
  key: CompositeSigningKey
): CompositeSignatureWire {
  const mPrime = compositeMPrime(PROFILE_P256_MLDSA65, payloadCanonDigestHex);

  // ECDSA-P256 over SHA3-256(M'), RFC 6979 deterministic: same key + M', same bytes.
  const ecdsaSig = signEcdsaP256Raw(key.p256Private, mPrime);
  // ML-DSA-65 over M' directly (empty context, no pre-hash).
  const mldsaSig = signMlDsa65(key.mldsaSecret, mPrime);

  return {
    alg: PROFILE_P256_MLDSA65,
    mode: "AND",
    signatures: [
      {
        alg: ALG_ECDSA_P256,
        encoding: "raw-rs-64",
        low_s: true,
        sig_b64: Buffer.from(ecdsaSig).toString("base64"),
      },
      {
        alg: ALG_MLDSA65,
        sig_b64: Buffer.from(mldsaSig).toString("base64"),
      },
    ],
  };
}
