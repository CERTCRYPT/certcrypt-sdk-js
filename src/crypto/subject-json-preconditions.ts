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
 * Field-set / value-discipline preconditions for the JSON-object subject
 * profiles, enforced BEFORE canonicalization.
 *
 * Copied byte-for-byte in behavior from
 * `certcrypt-verifier-toolkit-js/core/crypto/subject-json-preconditions.ts` so
 * the issuer-side `canonical_bytes(subject)` for JSON-object profiles matches the
 * verifier's. The toolkit does not export this module, so it is
 * vendored here (same rationale as `jcs.ts`).
 *
 * Each profile spec states that structural conformance is a *precondition of
 * canonicalization*, not a separable later check: `canonical_bytes(subject)` is
 * defined ONLY for an object satisfying the profile in full, and for any
 * other object the profile does not apply and the implementation MUST fail
 * closed (subject.collection/1, subject.ai-decision/1, and the no-number
 * discipline of subject.context-snapshot/1).
 */

/** Thrown when a JSON-object subject violates its profile precondition. */
export class SubjectPreconditionError extends Error {
  readonly profile: string;
  constructor(profile: string, detail: string) {
    super(`subject precondition failed for ${profile}: ${detail}`);
    this.name = "SubjectPreconditionError";
    this.profile = profile;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Recursively assert the string-only value discipline of the two JSON-object
 * profiles with closed, string-valued member sets (subject.collection/1 and
 * subject.ai-decision/1): every value at any depth (object members, array
 * elements) MUST be a JSON string, object, or array. A JSON number, boolean, or
 * null token anywhere is non-conformant. This is what keeps RFC 8785 free of
 * number serialization. subject.context-snapshot/1 uses the narrower
 * `assertNoJsonNumber` below.
 */
function assertStringOnly(profile: string, value: unknown, path: string): void {
  if (typeof value === "string") return;
  if (Array.isArray(value)) {
    value.forEach((el, i) => assertStringOnly(profile, el, `${path}[${i}]`));
    return;
  }
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) {
      assertStringOnly(profile, value[k], path ? `${path}.${k}` : k);
    }
    return;
  }
  // number, boolean, null, or undefined — all forbidden.
  const kind = value === null ? "null" : typeof value;
  throw new SubjectPreconditionError(
    profile,
    `value at ${path || "(root)"} is a JSON ${kind}; every value must be a string, object, or array (no numbers/booleans/nulls)`,
  );
}

const CARDINALITY_MAX = 18446744073709551615n; // 2^64 − 1

/**
 * subject.collection/1: exactly four members — `commitment_scheme`, `root`,
 * `declared_cardinality` and the `leaves[]` array, whose entries each declare their
 * own `profile` and `commitment_digest_hex`. Also checks the commitment-scheme-specific
 * `root` shape, the `declared_cardinality` grammar, and that the cardinality agrees
 * with the number of leaves.
 */
export function assertCollectionPrecondition(value: unknown): void {
  const P = "subject.collection/1";
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(P, "subject is not a JSON object");
  }
  const REQUIRED = ["commitment_scheme", "root", "declared_cardinality", "leaves"];
  const STRING_MEMBERS = ["commitment_scheme", "root", "declared_cardinality"];
  const keys = Object.keys(value);
  for (const k of REQUIRED) {
    if (!(k in value)) throw new SubjectPreconditionError(P, `missing member "${k}"`);
  }
  for (const k of keys) {
    if (!REQUIRED.includes(k)) {
      throw new SubjectPreconditionError(P, `unexpected member "${k}" (exactly four members allowed)`);
    }
    if (STRING_MEMBERS.includes(k) && typeof value[k] !== "string") {
      throw new SubjectPreconditionError(P, `member "${k}" must be a string`);
    }
  }
  // `leaves` is the one non-string member: an ordered array where each entry declares
  // its own profile and commitment (`subject.collection/1` §7.4). Its position IS the
  // leaf index, so the array is load-bearing.
  const leaves = value.leaves;
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new SubjectPreconditionError(P, `"leaves" must be a non-empty array`);
  }
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i] as Record<string, unknown> | null;
    if (typeof leaf !== "object" || leaf === null || Array.isArray(leaf)) {
      throw new SubjectPreconditionError(P, `"leaves[${i}]" must be an object`);
    }
    const lk = Object.keys(leaf);
    if (lk.length !== 2 || !("profile" in leaf) || !("commitment_digest_hex" in leaf)) {
      throw new SubjectPreconditionError(
        P,
        `"leaves[${i}]" must contain exactly "profile" and "commitment_digest_hex"`
      );
    }
    for (const k of lk) {
      if (typeof leaf[k] !== "string") {
        throw new SubjectPreconditionError(P, `"leaves[${i}].${k}" must be a string`);
      }
    }
    if (!/^[0-9a-f]{64}$/.test(leaf.commitment_digest_hex as string)) {
      throw new SubjectPreconditionError(
        P,
        `"leaves[${i}].commitment_digest_hex" must be 64 lowercase hex characters`
      );
    }
  }
  // declared_cardinality: canonical unsigned base-10, no sign, no leading
  // zeros, > 0, ≤ 2^64 − 1.
  const dc = value.declared_cardinality as string;
  if (!/^[1-9][0-9]*$/.test(dc)) {
    throw new SubjectPreconditionError(
      P,
      `"declared_cardinality" must be a canonical unsigned base-10 integer with no sign and no leading zeros`,
    );
  }
  if (BigInt(dc) > CARDINALITY_MAX) {
    throw new SubjectPreconditionError(P, `"declared_cardinality" exceeds 2^64 − 1`);
  }
  // §7.4.3: the economic layer bills on declared_cardinality, so it MUST agree with
  // the array rather than be derived from it.
  if (String(leaves.length) !== dc) {
    throw new SubjectPreconditionError(
      P,
      `"declared_cardinality" (${dc}) does not equal the number of leaves (${leaves.length})`,
    );
  }
  // For the sha3-256 merkle scheme, root is 64 lowercase hex chars.
  if (value.commitment_scheme === "collection.merkle-sha3-256/1") {
    if (!/^[0-9a-f]{64}$/.test(value.root as string)) {
      throw new SubjectPreconditionError(
        P,
        `"root" must be a 64-character lowercase hex string under collection.merkle-sha3-256/1`,
      );
    }
  }
  assertStringOnly(P, value, "");
}

/** subject.ai-decision/1 §7.4: the profiles an input or output may be declared under. */
export const AI_DECISION_IO_PROFILES: readonly string[] = [
  "subject.text/1",
  "subject.binary/1",
  "subject.email/1",
  "subject.ai-decision/1",
];

const HEX64 = /^[0-9a-f]{64}$/;
const AI_PART_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const MEDIA_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
const AI_MAX_PARTS = 256;
const AI_MAX_MAP_MEMBERS = 128;

/** subject.ai-decision/1 §7.3 canonical UTC millisecond timestamp syntax. */
const DECISION_TIME =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\.([0-9]{3})Z$/;

function canonicalDecisionTime(profile: string, value: unknown, member: string): string {
  if (typeof value !== "string") {
    throw new SubjectPreconditionError(profile, `member "${member}" must be a string`);
  }
  const m = DECISION_TIME.exec(value);
  if (!m) {
    throw new SubjectPreconditionError(
      profile,
      `"${member}" must be UTC with milliseconds (YYYY-MM-DDTHH:MM:SS.sssZ)`,
    );
  }
  const [year, month, day, hour, minute, second, millisecond] = m.slice(1).map(Number);
  if (year === 0) {
    throw new SubjectPreconditionError(profile, `"${member}" is not a real Gregorian date`);
  }
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (day > monthDays[month - 1]) {
    throw new SubjectPreconditionError(profile, `"${member}" is not a real Gregorian date`);
  }
  void hour;
  void minute;
  void second;
  void millisecond;
  return value;
}

/**
 * subject.ai-decision/1: exact member set with the required/optional split, flat
 * string-valued nested objects, the all-strings value discipline, and the syntax
 * preconditions of §7.3 (salted part commitments, the input/output `profile`,
 * and `decided_at`).
 */
export function assertAiDecisionPrecondition(value: unknown): void {
  const P = "subject.ai-decision/1";
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(P, "record is not a JSON object");
  }
  // String-only first: it is the discipline that keeps JCS number-free and it
  // subsumes "no boolean/null" for every member below.
  assertStringOnly(P, value, "");

  const REQUIRED = [
    "profile",
    "decision_id",
    "decided_at",
    "model",
    "observation_scope",
    "input",
    "output",
    "decision",
  ];
  const OPTIONAL = ["parameters", "context", "started_at", "actor_id", "policy_ref"];
  const allowed = new Set([...REQUIRED, ...OPTIONAL]);
  for (const k of REQUIRED) {
    if (!(k in value)) throw new SubjectPreconditionError(P, `missing required member "${k}"`);
  }
  for (const k of Object.keys(value)) {
    if (!allowed.has(k)) {
      throw new SubjectPreconditionError(P, `unexpected member "${k}"`);
    }
  }
  if (value.profile !== P) {
    throw new SubjectPreconditionError(P, `"profile" must equal "${P}"`);
  }
  for (const k of ["profile", "decision_id", "decision", "observation_scope"] as const) {
    if (typeof value[k] !== "string") {
      throw new SubjectPreconditionError(P, `member "${k}" must be a string`);
    }
  }
  if (!AI_PART_ID.test(value.decision_id as string)) {
    throw new SubjectPreconditionError(P, `"decision_id" is not a canonical identifier`);
  }
  if ((value.decision as string).length === 0) {
    throw new SubjectPreconditionError(P, `"decision" must not be empty`);
  }
  if (value.observation_scope !== "client" && value.observation_scope !== "runtime") {
    throw new SubjectPreconditionError(
      P,
      `"observation_scope" must be "client" or "runtime"`,
    );
  }
  const decidedAt = canonicalDecisionTime(P, value.decided_at, "decided_at");
  if ("started_at" in value) {
    const startedAt = canonicalDecisionTime(P, value.started_at, "started_at");
    if (startedAt > decidedAt) {
      throw new SubjectPreconditionError(P, `"started_at" must not be after "decided_at"`);
    }
  }
  // model: object with string id + provider, optional string version, no other members.
  assertNestedStringObject(P, value.model, "model", ["id", "provider"], ["version"]);
  const model = value.model as Record<string, string>;
  for (const member of ["id", "provider", ...(Object.hasOwn(model, "version") ? ["version"] : [])]) {
    if (model[member].length === 0) {
      throw new SubjectPreconditionError(P, `"model.${member}" must not be empty`);
    }
  }
  const seenIds = new Set<string>();
  const seenNonces = new Set<string>();
  let partCount = 0;
  for (const side of ["input", "output"] as const) {
    const parts = value[side];
    if (!Array.isArray(parts) || parts.length === 0) {
      throw new SubjectPreconditionError(P, `"${side}" must be a non-empty array`);
    }
    partCount += parts.length;
    for (let i = 0; i < parts.length; i++) {
      const name = `${side}[${i}]`;
      assertNestedStringObject(
        P,
        parts[i],
        name,
        ["id", "role", "media_type", "profile", "material_nonce_hex", "commitment_digest_hex"],
        [],
      );
      const part = parts[i] as Record<string, string>;
      if (!AI_PART_ID.test(part.id)) {
        throw new SubjectPreconditionError(P, `"${name}.id" is not a canonical part identifier`);
      }
      if (seenIds.has(part.id)) {
        throw new SubjectPreconditionError(P, `material id ${JSON.stringify(part.id)} is duplicated`);
      }
      seenIds.add(part.id);
      if (part.role.length === 0) {
        throw new SubjectPreconditionError(P, `"${name}.role" must not be empty`);
      }
      if (!MEDIA_TYPE.test(part.media_type)) {
        throw new SubjectPreconditionError(
          P,
          `"${name}.media_type" must be a lowercase MIME essence without parameters`,
        );
      }
      if (!AI_DECISION_IO_PROFILES.includes(part.profile)) {
        throw new SubjectPreconditionError(P, `"${name}.profile" is not an admitted material profile`);
      }
      if (!HEX64.test(part.material_nonce_hex)) {
        throw new SubjectPreconditionError(P, `"${name}.material_nonce_hex" must be 64 lowercase hex characters`);
      }
      if (seenNonces.has(part.material_nonce_hex)) {
        throw new SubjectPreconditionError(P, `material nonce ${JSON.stringify(part.material_nonce_hex)} is duplicated`);
      }
      seenNonces.add(part.material_nonce_hex);
      if (!HEX64.test(part.commitment_digest_hex)) {
        throw new SubjectPreconditionError(P, `"${name}.commitment_digest_hex" must be 64 lowercase hex characters`);
      }
    }
  }
  if (partCount > AI_MAX_PARTS) {
    throw new SubjectPreconditionError(P, `input and output together may contain at most ${AI_MAX_PARTS} parts`);
  }
  for (const mapName of ["parameters", "context"] as const) {
    if (mapName in value) assertFlatStringMap(P, value[mapName], mapName);
  }
  for (const k of ["actor_id", "policy_ref"] as const) {
    if (k in value && typeof value[k] !== "string") {
      throw new SubjectPreconditionError(P, `optional member "${k}" must be a string`);
    }
  }
}

function assertFlatStringMap(profile: string, value: unknown, name: string): void {
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(profile, `"${name}" must be an object when present`);
  }
  const entries = Object.entries(value);
  if (entries.length > AI_MAX_MAP_MEMBERS) {
    throw new SubjectPreconditionError(profile, `"${name}" may contain at most ${AI_MAX_MAP_MEMBERS} members`);
  }
  for (const [k, v] of entries) {
    if (typeof v !== "string") {
      throw new SubjectPreconditionError(profile, `"${name}.${k}" must be a string`);
    }
  }
}

function assertNestedStringObject(
  profile: string,
  obj: unknown,
  name: string,
  required: string[],
  optional: string[],
): void {
  if (!isPlainObject(obj)) {
    throw new SubjectPreconditionError(profile, `member "${name}" must be an object`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const k of required) {
    if (!(k in obj)) throw new SubjectPreconditionError(profile, `"${name}" missing member "${k}"`);
  }
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) {
      throw new SubjectPreconditionError(profile, `"${name}" has unexpected member "${k}"`);
    }
    if (typeof obj[k] !== "string") {
      throw new SubjectPreconditionError(profile, `"${name}.${k}" must be a string`);
    }
  }
}

/**
 * subject.context-snapshot/1: the only precondition this profile fixes at
 * the canonicalization boundary is that the value is a JSON object with no JSON
 * number at any depth (booleans and nulls are permitted). It does not fix a member set — the snapshot
 * shape is governed by the higher-layer protocol (CCVP/1), not this profile.
 */
export function assertContextSnapshotPrecondition(value: unknown): void {
  const P = "subject.context-snapshot/1";
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(P, "snapshot is not a JSON object");
  }
  assertNoJsonNumber(P, value, "");
}

/**
 * `subject.context-snapshot/1` §7.1: no JSON NUMBER at any depth. Booleans and
 * nulls are permitted.
 *
 * Narrower than `assertStringOnly` on purpose, and the difference is normative.
 * That function serves `subject.collection/1` and `subject.ai-decision/1`, whose
 * member sets are closed and entirely string-valued. This profile fixes no member
 * set — the snapshot shape belongs to CCVP/1 — and §7 requires preserving "the
 * exact string, boolean, array, object, and null semantics of the input", while
 * §8 forbids coercing "booleans or nulls into strings". CCVP/1 §7.1 relies on
 * this: its normative entry example carries `valid_to: null` for an open-ended
 * eligibility window, and `revoked_at: null` for one never revoked.
 *
 * Rejecting nulls here would make the governing protocol's own example
 * non-conformant, and would force an open window to be spelled as a string —
 * exactly the coercion §8 prohibits. Only numbers are excluded, because number
 * serialization is the one RFC 8785 divergence vector across languages.
 */
function assertNoJsonNumber(profile: string, value: unknown, path: string): void {
  if (typeof value === "number") {
    throw new SubjectPreconditionError(
      profile,
      `value at ${path || "(root)"} is a JSON number; every numeric-looking value ` +
        `must be carried as a JSON string so RFC 8785 canonicalization converges ` +
        `across languages`,
    );
  }
  if (Array.isArray(value)) {
    value.forEach((el, i) => assertNoJsonNumber(profile, el, `${path}[${i}]`));
    return;
  }
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) {
      assertNoJsonNumber(profile, value[k], path ? `${path}.${k}` : k);
    }
  }
}
