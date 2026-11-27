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
 * Configuration guards, and the `unlinkable` key mode.
 *
 * These are the refusals an INTEGRATOR provokes — a missing option, a mode
 * configured with nothing to back it, a rules_version this SDK does not
 * implement. They matter because each one protects a property that fails SILENTLY otherwise:
 *
 *   - `unlinkable` with a one-leaf tree would reuse the single leaf on every
 *     certificate, quietly losing the exact property the mode exists to provide —
 *     and no verifier can detect a repeated leaf;
 *   - a commitment TTL that is guessed produces certificates a verifier rejects
 *     for `COMMITMENT_TTL_VALID`, months later, in someone else's hands;
 *   - a missing `holderId` would attribute the emission to nobody.
 *
 * Each case asserts the MESSAGE, not just that something threw: these errors are
 * read by a human wiring an integration, so their usefulness is the contract.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Certcrypt, InMemoryLeafStore, registerRulesDomain } from "./issuer.js";

const SEED = "22".repeat(32);
const RULES = "rules/2026-01";
const FINGERPRINT = "ab".repeat(32);

/** A fetch that must never be reached: these guards fire before any network call. */
const unreachableFetch = (async () => {
  throw new Error("no request should leave the process for a config guard");
}) as typeof fetch;

function opts(extra: Record<string, unknown> = {}) {
  return {
    nodeBaseUrl: "https://node.test",
    fetch: unreachableFetch,
    keysetSeed: SEED,
    integrationKey: "CCI-TEST-0001",
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    ...extra,
  } as never;
}

/**
 * Options carrying a PRE-OBTAINED binding plus the identifiers activation would
 * have taught. Several guards fire only after activation, so a case about them
 * needs a bound issuer — this reaches them without any network round-trip.
 */
function boundOpts(extra: Record<string, unknown> = {}) {
  return opts({
    integrationKey: undefined,
    poolId: "pool-1",
    holderId: "holder-1",
    signedLevel1: {
      level1_binding: {
        system_id: "certcrypt",
        rules_version: RULES,
        system_root_fingerprint: FINGERPRINT,
        authorized_role: "issuer",
        authorization_issuer_kid: "kid-l1",
        valid_from: "2020-01-01T00:00:00Z",
        valid_until: "2099-01-01T00:00:00Z",
        holder_key_set_root: "00".repeat(32),
      },
      level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
    },
    ...extra,
  });
}

// --- key modes -------------------------------------------------------------

test("unlinkable mode refuses a tree too small to give each certificate its own leaf", () => {
  // treeSize 1 means one leaf, reused forever — `stable` behavior under the
  // `unlinkable` name. A verifier cannot detect leaf reuse, so this must fail at
  // construction rather than silently degrade the privacy property.
  assert.throws(
    () => new Certcrypt(opts({ mode: "unlinkable", treeSize: 1 })),
    /treeSize >= 2/
  );
});

test("unlinkable mode refuses construction without a leaf store", () => {
  // No default: an in-memory store restarts at zero and silently reuses every
  // leaf it handed out, which no verifier can detect. The guard fires at
  // construction, before any key is used.
  assert.throws(
    () => new Certcrypt(opts({ mode: "unlinkable", treeSize: 4 })),
    /mode "unlinkable" requires a leafStore/
  );
});

test("stable mode is the default and needs no leaf store", () => {
  const issuer = new Certcrypt(opts());
  assert.ok(issuer);
});

test("an explicit leaf store is honored in unlinkable mode", () => {
  const store = new InMemoryLeafStore();
  const issuer = new Certcrypt(opts({ mode: "unlinkable", treeSize: 4, leafStore: store }));
  assert.ok(issuer);
});

test("InMemoryLeafStore hands out strictly increasing, never-reused indices", () => {
  return (async () => {
    // The whole point of the store. A repeat here is the silent failure the
    // unlinkable mode exists to prevent, so pin monotonicity explicitly.
    const store = new InMemoryLeafStore();
    const seen = new Set<number>();
    let previous = -1;
    for (let i = 0; i < 50; i++) {
      const leaf = await store.nextLeaf();
      assert.ok(leaf > previous, `leaf ${leaf} must be greater than ${previous}`);
      assert.ok(!seen.has(leaf), `leaf ${leaf} was handed out twice`);
      seen.add(leaf);
      previous = leaf;
    }
  })();
});

// --- issuance guards -------------------------------------------------------

test("issue() refuses an empty subjects[] set", () => {
  return (async () => {
    const issuer = new Certcrypt(boundOpts());
    await assert.rejects(
      () => issuer.issue({ subjects: [] } as never),
      /non-empty subjects/
    );
  })();
});

test("a rules_version with no known TTL is refused at construction", () => {
  // The TTL is a public rule (the verifier requires expires_at === issued_at +
  // ttl), so guessing it produces certificates that fail verification later.
  //
  // The rules-domain guard catches this before the TTL guard does, and catches
  // strictly more: an unknown TTL is only a symptom of the SDK not implementing
  // that rules domain. Refusing at construction means no key is derived and no capacity is
  // touched (rules-domain/1 §14.2).
  assert.throws(
    () => new Certcrypt(boundOpts({ rulesVersion: "rules/does-not-exist" })),
    /does not implement rules_version/
  );
});

test("an explicit commitmentTtlSeconds does not unblock an unknown rules_version", () => {
  // Stating the TTL is not enough to issue under a rules domain the SDK does not
  // implement, deliberately.
  //
  // The TTL is only the last missing parameter; supplying it does not make this
  // SDK an implementation of the rules domain being claimed. Emitting under rules
  // it does not implement produces artifacts that verify perfectly and attest to
  // behavior that never happened — the one failure mode no verifier can detect
  // (rules-domain/1 §14.2). The refusal is at construction, before a key is
  // derived or capacity is touched. A deployment that needs another domain
  // registers it with `registerRulesDomain` and states the TTL.
  assert.throws(
    () =>
      new Certcrypt(
        boundOpts({ rulesVersion: "rules/does-not-exist", commitmentTtlSeconds: 86_400 })
      ),
    /does not implement rules_version/
  );
});

test("issue() requires a systemId, and says what it is for", () => {
  return (async () => {
    // NOTE the ordering this pins: the systemId guard fires AFTER activation, not
    // at construction, so reaching it needs a binding in hand. Supplying a
    // pre-obtained one (plus the identifiers activation would have taught) gets
    // there without a network round-trip.
    const issuer = new Certcrypt(
      opts({
        systemId: undefined,
        integrationKey: undefined,
        poolId: "pool-1",
        holderId: "holder-1",
        signedLevel1: {
          level1_binding: {
            system_id: "certcrypt",
            rules_version: RULES,
            system_root_fingerprint: FINGERPRINT,
            authorized_role: "issuer",
            authorization_issuer_kid: "kid-l1",
            valid_from: "2020-01-01T00:00:00Z",
            valid_until: "2099-01-01T00:00:00Z",
            holder_key_set_root: "00".repeat(32),
          },
          level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
        },
      })
    );
    await assert.rejects(
      () =>
        issuer.issue({
          subjects: [{ profile: "subject.text/1", material: new TextEncoder().encode("x") }],
        } as never),
      /systemId/
    );
  })();
});

test("a pre-obtained binding without a holderId is refused", () => {
  return (async () => {
    // holder_id is LEARNED from activation and is what emission is attributed to.
    // Supplying a bare signedLevel1 by hand skips that, so the SDK refuses instead
    // of emitting work attributed to nobody.
    const issuer = new Certcrypt(
      opts({
        integrationKey: undefined,
        // pool_id is guarded FIRST; supply it so this case reaches the holder_id
        // guard it is actually about.
        poolId: "pool-1",
        signedLevel1: {
          level1_binding: {
            system_id: "certcrypt",
            rules_version: RULES,
            system_root_fingerprint: FINGERPRINT,
            authorized_role: "issuer",
            authorization_issuer_kid: "kid-l1",
            valid_from: "2020-01-01T00:00:00Z",
            valid_until: "2099-01-01T00:00:00Z",
            holder_key_set_root: "00".repeat(32),
          },
          level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
        },
      })
    );
    await assert.rejects(
      () =>
        issuer.issue({
          subjects: [{ profile: "subject.text/1", material: new TextEncoder().encode("x") }],
        } as never),
      /holder_id/
    );
  })();
});

// ---------------------------------------------------------------------------
// Runtime rules-domain registration
//
// A deployment may run under a rules domain it registers at runtime instead of
// one from the SDK's built-in list. The domain then comes from whoever runs the
// SDK.
//
// What these tests pin is that the escape hatch did NOT become a hole: an
// unregistered domain is still refused, and the refusal still lands at
// construction, before a key is derived.
// ---------------------------------------------------------------------------

test("an unregistered rules domain is still refused after registration exists", () => {
  // The load-bearing case. Registration must not turn the gate into a
  // formality: registering one domain says nothing about any other.
  registerRulesDomain("rules/some-other-deployment");
  assert.throws(
    () => new Certcrypt(boundOpts({ rulesVersion: "rules/still-unknown" })),
    /does not implement rules_version/,
    "registering one domain must not admit a different one"
  );
});

test("a registered rules domain passes the construction gate", () => {
  registerRulesDomain("rules/test-deployment");
  assert.doesNotThrow(
    () => new Certcrypt(boundOpts({ rulesVersion: "rules/test-deployment" })),
    "a registered domain must construct"
  );
});

test("registration refuses input that is not a rules domain", () => {
  // Not cosmetic: `rules_version` travels inside signed artifacts. A malformed
  // one produces a signature over a claim nobody can resolve.
  assert.throws(() => registerRulesDomain(""), /non-empty/);
  assert.throws(() => registerRulesDomain("2026-01"), /must start with "rules\/"/);
});
