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
 * ECDSA P-256 (secp256r1) signing — the classical component of the CERTCRYPT
 * Composite Signature Profile (`certcrypt-composite-p256-mldsa65-v1`), issuer
 * side. Signer counterpart to
 * `certcrypt-verifier-toolkit-js/core/crypto/ecdsa-p256.ts`.
 *
 * Wire contract (must interoperate with every other implementation):
 *   - curve P-256 / secp256r1, hash **SHA3-256** over the message (NOT SHA-2);
 *   - signature encoding `raw-rs-64`: r || s, 64 bytes (32+32), big-endian, NOT DER;
 *   - low-s NORMATIVE: the producer MUST emit s ≤ n/2, so s is normalized here
 *     (the verifier rejects high-s outright).
 *   - public key on the wire: SEC1 uncompressed (65B, 0x04 prefix), base64.
 *
 * Signing is RFC 6979 deterministic, with H = SHA3-256 for both the prehash and
 * the nonce's HMAC (conformance family `ecdsa-p256-deterministic`): one key over
 * one message yields exactly one signature. node's `crypto.sign` draws a random
 * nonce, so the signature is computed with `@noble/curves` instead; node:crypto
 * still carries keys and the local self-check verify.
 */
import { ecdsa } from "@noble/curves/abstract/weierstrass.js";
import { p256 } from "@noble/curves/nist.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import {
  createECDH,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

// secp256r1 group order n, and n/2 (the low-s ceiling, inclusive).
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

/** An ECDSA P-256 keypair as node KeyObjects plus the wire public key. */
export interface EcdsaP256KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** SEC1 uncompressed (65B, 0x04-prefixed) public key, base64 — the wire form. */
  publicKeyB64: string;
}

/** Generate a fresh ECDSA P-256 keypair (dev/test; production keys via KMS). */
export function generateEcdsaP256KeyPair(): EcdsaP256KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  return {
    privateKey,
    publicKey,
    publicKeyB64: publicKeySec1UncompressedB64(publicKey),
  };
}

/** Export a P-256 public KeyObject as SEC1 uncompressed (65B) base64. */
export function publicKeySec1UncompressedB64(publicKey: KeyObject): string {
  // JWK gives raw x/y coordinates; assemble 0x04 || X(32) || Y(32).
  const jwk = publicKey.export({ format: "jwk" });
  if (!jwk.x || !jwk.y) {
    throw new Error("ECDSA-P256 public key JWK missing x/y coordinates");
  }
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  if (x.length !== 32 || y.length !== 32) {
    throw new Error(
      `ECDSA-P256 coordinates must be 32 bytes each (got x=${x.length}, y=${y.length})`
    );
  }
  return Buffer.concat([Buffer.from([0x04]), x, y]).toString("base64");
}

/** Load a P-256 private key from PKCS#8 DER/PEM (for KMS-provisioned keys). */
export function privateKeyFromPkcs8(pkcs8: Buffer | string): KeyObject {
  return createPrivateKey(pkcs8);
}

/**
 * Build a P-256 private KeyObject DETERMINISTICALLY from a 32-byte scalar `d`
 * (1 ≤ d < n). Used to derive a stable issuer key from a master seed — the same
 * seed always yields the same signing identity, with no stored key material.
 *
 * The public point (x, y) is derived from `d` via ECDH (`crypto.createECDH`,
 * which does the scalar × G multiplication), then a JWK EC private key
 * {crv, d, x, y} is imported: a pure-`node:crypto` way to go from a raw scalar to
 * a signing KeyObject.
 *
 * Callers MUST pass a scalar already reduced into [1, n): see
 * `scalarFromSeedMaterial`, which folds arbitrary seed bytes into range.
 */
export function privateKeyFromScalar(scalar: Uint8Array): KeyObject {
  if (scalar.length !== 32) {
    throw new Error(`P-256 scalar must be 32 bytes (got ${scalar.length})`);
  }
  const d = beBytesToBigInt(scalar);
  if (d <= 0n || d >= P256_N) {
    throw new Error("P-256 scalar out of range [1, n) — reduce it first");
  }
  // Derive the public point from d: createECDH lets us set the private key and
  // read back the SEC1-uncompressed public key (0x04 || X || Y).
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(scalar));
  const pub = ecdh.getPublicKey(); // 65B SEC1 uncompressed
  const x = pub.subarray(1, 33);
  const y = pub.subarray(33, 65);
  const toB64Url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
  return createPrivateKey({
    key: {
      kty: "EC",
      crv: "P-256",
      d: toB64Url(scalar),
      x: toB64Url(x),
      y: toB64Url(y),
    },
    format: "jwk",
  });
}

/**
 * Domain-separation info string for deriving the P-256 half of a composite key
 * from a 32-byte master seed.
 *
 * Load-bearing, and pinned by the conformance contract
 * (`fixtures/primitives/key-derivation`): whatever derives the published key and
 * every SDK MUST derive byte-identically, or the public key published in the manifest
 * is not the one this seed produces.
 */
export const P256_DERIVE_INFO = "certcrypt/composite/p256/v1";

/**
 * HKDF (RFC 5869) with SHA3-256, no salt.
 *
 * Written out rather than taken from node's `hkdf`, which does not offer SHA3 in
 * every supported runtime. This derivation is part of the byte contract, so a few
 * lines a reader can check against RFC 5869 beat a dependency whose hash choice
 * is an argument someone can change.
 */
function hkdfSha3_256(ikm: Uint8Array, info: string, length: number): Uint8Array {
  const hashLen = 32;
  const prk = createHmac("sha3-256", Buffer.alloc(hashLen)).update(ikm).digest();
  const infoBytes = Buffer.from(info, "utf-8");
  const out: Buffer[] = [];
  let block = Buffer.alloc(0);
  let counter = 1;
  let produced = 0;
  while (produced < length) {
    block = createHmac("sha3-256", prk)
      .update(Buffer.concat([block, infoBytes, Buffer.from([counter])]))
      .digest();
    out.push(block);
    produced += block.length;
    counter += 1;
  }
  return new Uint8Array(Buffer.concat(out).subarray(0, length));
}

/**
 * Deterministic P-256 signing key from a 32-byte master seed.
 *
 * HKDF-SHA3-256 with explicit domain separation, expanded to 48 bytes and reduced
 * mod n. The oversampling past the 32-byte field removes the modular bias of
 * reducing exactly 256 bits; a result of 0 maps to 1, so the scalar is always in
 * [1, n-1].
 *
 * The SAME seed also derives the ML-DSA-65 half (FIPS 204 KeyGen, seed used
 * verbatim). The distinct HKDF `info` keeps the two derivations separated, so one
 * custodied seed materializes the whole composite identity without either
 * component leaking into the other.
 *
 * Note the difference from {@link scalarFromSeedMaterial}, which folds arbitrary
 * bytes with `% (n-1) + 1`. That is a different reduction and yields a different
 * key: it is for callers holding their own material, not for the composite
 * identity. Only this function reproduces the contract's vectors.
 */
export function signingKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.length !== 32) {
    throw new Error(`master seed must be 32 bytes (got ${seed.length})`);
  }
  const okm = hkdfSha3_256(seed, P256_DERIVE_INFO, 48);
  let scalar = beBytesToBigInt(okm) % P256_N;
  if (scalar === 0n) scalar = 1n;
  return privateKeyFromScalar(bigIntTo32Be(scalar));
}

/**
 * Fold arbitrary seed-derived bytes into a valid P-256 scalar in [1, n). Reduces
 * mod (n-1) and adds 1 so the result is never 0 and never ≥ n. Deterministic.
 */
export function scalarFromSeedMaterial(material: Uint8Array): Uint8Array {
  const v = beBytesToBigInt(material) % (P256_N - 1n);
  return bigIntTo32Be(v + 1n);
}

/** Derive the SEC1-uncompressed wire public key from a P-256 private key. */
export function publicKeyB64FromPrivate(privateKey: KeyObject): string {
  return publicKeySec1UncompressedB64(createPublicKey(privateKey));
}

function beBytesToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) acc = (acc << 8n) | BigInt(b);
  return acc;
}

function bigIntTo32Be(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * P-256 ECDSA with SHA3-256 as the curve hash: it prehashes the message and keys
 * the RFC 6979 HMAC-DRBG, so the nonce is HMAC-SHA3-256 as RFC 6979 §3.2
 * prescribes for a SHA3-256 message hash. No extra entropy: deterministic.
 */
const P256_SHA3 = ecdsa(p256.Point, sha3_256);

/** The private scalar of a P-256 KeyObject, as 32 big-endian bytes. */
function privateScalar(privateKey: KeyObject): Uint8Array {
  const jwk = privateKey.export({ format: "jwk" });
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d) {
    throw new Error("ECDSA-P256 signing needs a P-256 private key");
  }
  const d = Buffer.from(jwk.d, "base64url");
  if (d.length !== 32) {
    throw new Error(`P-256 private scalar must be 32 bytes (got ${d.length})`);
  }
  return new Uint8Array(d);
}

/**
 * Sign `message` with a P-256 private key, returning a `raw-rs-64` signature
 * (r||s, 64 bytes) normalized to low-s (s ≤ n/2).
 *
 * The message is hashed once with SHA3-256 and the nonce is RFC 6979
 * deterministic with HMAC-SHA3-256, so the same key and message always give the
 * same 64 bytes (conformance family `ecdsa-p256-deterministic`).
 */
export function signEcdsaP256Raw(
  privateKey: KeyObject,
  message: Uint8Array
): Uint8Array {
  const sig = P256_SHA3.sign(message, privateScalar(privateKey), {
    prehash: true,
    lowS: true,
    extraEntropy: false,
    format: "compact",
  });
  if (sig.length !== 64) {
    throw new Error(`expected raw-rs-64 signature (64 bytes), got ${sig.length}`);
  }
  const r = beBytesToBigInt(sig.subarray(0, 32));
  let s = beBytesToBigInt(sig.subarray(32, 64));
  // Low-s normalization: if s > n/2, replace with n - s (the equivalent low-s
  // signature). The verifier rejects high-s, so this is mandatory on produce.
  // `lowS: true` already does it; kept explicit because the rule is normative.
  if (s > P256_HALF_N) {
    s = P256_N - s;
  }
  const out = new Uint8Array(64);
  out.set(bigIntTo32Be(r), 0);
  out.set(bigIntTo32Be(s), 32);
  return out;
}

/**
 * Local self-check verify (tests / minter self-verification). The production
 * trust verdict is the composite check in the verifier toolkit; this only mirrors
 * its ECDSA primitive (SHA3-256, raw-rs-64, low-s enforced).
 */
export function verifyEcdsaP256Raw(
  publicKeyB64: string,
  message: Uint8Array,
  sig: Uint8Array
): boolean {
  if (sig.length !== 64) return false;
  const s = beBytesToBigInt(sig.subarray(32, 64));
  if (s > P256_HALF_N || s === 0n) return false;
  const r = beBytesToBigInt(sig.subarray(0, 32));
  if (r === 0n || r >= P256_N) return false;

  const pub = Buffer.from(publicKeyB64, "base64");
  // SEC1 uncompressed → SPKI via node import.
  const keyObject = createPublicKey({
    key: Buffer.concat([sec1SpkiPrefix(pub.length), pub]),
    format: "der",
    type: "spki",
  });
  return cryptoVerify(
    "sha3-256",
    Buffer.from(message),
    { key: keyObject, dsaEncoding: "ieee-p1363" },
    Buffer.from(sig)
  );
}

const P256_ALG_ID = Buffer.from(
  "301306072a8648ce3d020106082a8648ce3d030107",
  "hex"
);

function sec1SpkiPrefix(pointLen: number): Buffer {
  const bitString = Buffer.from([0x03, pointLen + 1, 0x00]);
  const body = Buffer.concat([P256_ALG_ID, bitString]);
  return Buffer.concat([Buffer.from([0x30, body.length + pointLen]), body]);
}
