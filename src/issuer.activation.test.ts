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
 * `Certcrypt.activate()` / `ensureActivated()` — the TOFU path that binds this
 * issuer's key-set root to its one-time integration key.
 *
 * Split out of `issuer.test.ts` by topic: that file covers issuance, this one
 * covers activation's own contract. It is worth its own
 * cases because the properties here are the ones an issuer relies on WITHOUT ever
 * testing them itself — the deploy just works, until the day it does not:
 *
 *   - a cold restart re-activates from config alone, with nothing persisted;
 *   - the request PROVES possession of the root it asks the server to bind,
 *     because activation travels through a node and an unsigned root would just
 *     be a body field in transit;
 *   - the SDK sends no `valid_from`: the service fixes it at first activation,
 *     so a replay answers with the SAME binding instead of a fresh one per boot;
 *   - the binding store is a CACHE: losing it costs a round-trip, never
 *     correctness.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { Certcrypt } from "./issuer.js";
import { HolderKeySet } from "./artifacts/holder-keyset.js";
import { CertcryptNodeError } from "./client.js";

const SEED = "11".repeat(32);
const RULES = "rules/2026-01";
const FINGERPRINT = "ab".repeat(32);

/** Captures what the SDK actually sent to `/v1/activate`. */
type ActivateBody = {
  code: string;
  holder_key_set_root: string;
  key_set_possession_b64?: string;
  key_set_disclosure?: unknown;
  valid_from?: string;
};

function fakeApi(
  opts: {
    activateStatus?: number;
    activateError?: unknown;
    /** Rewrites the 200 body before it is sent; a string is sent as raw text. */
    activateBody?: (body: Record<string, unknown>) => unknown;
  } = {},
) {
  const seen: { activate: ActivateBody[] } = { activate: [] };
  const keySet = HolderKeySet.fromMasterSeed(SEED, 1);
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const json = (body: unknown, status = 200) =>
      ({
        ok: status >= 200 && status < 300,
        status,
        json: async () => body,
        text: async () => JSON.stringify(body),
      }) as Response;

    if (url.includes("/v1/activate")) {
      seen.activate.push(JSON.parse(String(init?.body ?? "{}")));
      if (opts.activateStatus && opts.activateStatus >= 400) {
        return json(opts.activateError ?? { error: "activation refused" }, opts.activateStatus);
      }
      const ok: Record<string, unknown> = {
        authorization_id: "auth-1",
        holder_key_set_root: keySet.root,
        level1_binding: {
          system_id: "certcrypt",
          rules_version: RULES,
          system_root_fingerprint: FINGERPRINT,
          authorized_role: "issuer",
          authorization_issuer_kid: "kid-l1",
          valid_from: "2020-01-01T00:00:00Z",
          valid_until: "2099-01-01T00:00:00Z",
          holder_key_set_root: keySet.root,
        },
        level1_signature: { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65", sig_b64: "c2ln" }] },
        holder_id: "holder-1",
        pool_id: "pool-1",
        status: "redeemed",
      };
      const body = opts.activateBody ? opts.activateBody(ok) : ok;
      if (typeof body === "string") {
        return {
          ok: true,
          status: 200,
          json: async () => JSON.parse(body),
          text: async () => body,
        } as Response;
      }
      return json(body);
    }
    return json({ error: "unexpected call" }, 404);
  }) as typeof fetch;
  return { fetchImpl, seen, keySet };
}

function issuerWith(fetchImpl: typeof fetch, extra: Record<string, unknown> = {}) {
  return new Certcrypt({
    nodeBaseUrl: "https://node.test",
    fetch: fetchImpl,
    keysetSeed: SEED,
    integrationKey: "CCI-TEST-0001",
    rulesVersion: RULES,
    systemRootFingerprint: FINGERPRINT,
    systemId: "certcrypt",
    mode: "stable",
    ...extra,
  } as never);
}

test("activate() binds, and a second call is a no-op (idempotent in-process)", () => {
  return (async () => {
    const { fetchImpl, seen } = fakeApi();
    const issuer = issuerWith(fetchImpl);
    const first = await issuer.activate();
    const second = await issuer.activate();
    assert.ok(first, "activation must return the binding");
    assert.equal(second, first, "a second call must reuse the in-memory binding");
    assert.equal(seen.activate.length, 1, "it must not re-hit the server once bound");
  })();
});

test("the activation request PROVES possession of the root it asks to bind", () => {
  return (async () => {
    // Activation travels THROUGH a node. An unsigned root would be just a body
    // field in transit, so anyone relaying could swap it. The request must carry a
    // leaf signature over the code AND the root.
    const { fetchImpl, seen, keySet } = fakeApi();
    await issuerWith(fetchImpl).activate();
    const body = seen.activate[0]!;
    assert.equal(body.holder_key_set_root, keySet.root, "it binds the root derived from the seed");
    assert.ok(body.key_set_possession_b64, "a possession signature is mandatory");
    assert.ok(body.key_set_disclosure, "a leaf disclosure must accompany the signature");
  })();
});

test("activation sends no valid_from: the service fixes it, so a replay gets the same binding", () => {
  return (async () => {
    // valid_from is signed INTO the binding. A date the SDK chose per start
    // would produce a different authorization_id on every boot; the service
    // fixes it at first activation and answers a same-root replay with that
    // binding.
    const a = fakeApi();
    const b = fakeApi();
    await issuerWith(a.fetchImpl).activate();
    await issuerWith(b.fetchImpl).activate();
    assert.equal(a.seen.activate[0]!.valid_from, undefined, "the SDK chooses no valid_from");
    assert.equal(b.seen.activate[0]!.valid_from, undefined, "the SDK chooses no valid_from");
  })();
});

test("a cold restart re-activates from config alone — nothing persisted", () => {
  return (async () => {
    // The property the docs promise: `keysetSeed` + `integrationKey` are the whole
    // boot credential. A brand-new instance (no store, no shared state) must bind
    // again by replaying the same key against the same derived root.
    const { fetchImpl, seen } = fakeApi();
    await issuerWith(fetchImpl).activate();
    await issuerWith(fetchImpl).activate(); // a "restart": a fresh instance
    assert.equal(seen.activate.length, 2, "the restart re-activates");
    assert.equal(
      seen.activate[0]!.holder_key_set_root,
      seen.activate[1]!.holder_key_set_root,
      "the same seed must derive the same root, so the replay is idempotent server-side"
    );
    assert.equal(seen.activate[0]!.code, seen.activate[1]!.code);
  })();
});

test("without an integrationKey, activation fails with an actionable message", () => {
  return (async () => {
    const { fetchImpl } = fakeApi();
    const issuer = issuerWith(fetchImpl, { integrationKey: undefined });
    await assert.rejects(() => issuer.activate(), /integrationKey/);
  })();
});

test("a server refusal surfaces instead of leaving a half-activated issuer", () => {
  return (async () => {
    // The 409 case in practice: the one-time code was already TOFU-bound to a
    // DIFFERENT key-set root, so this seed may not claim it. The SDK must not
    // swallow that into a silently unusable state.
    const { fetchImpl } = fakeApi({
      activateStatus: 409,
      activateError: { error: "code already consumed by another root" },
    });
    const issuer = issuerWith(fetchImpl);
    await assert.rejects(() => issuer.activate());
  })();
});

test("the binding store is a cache: a load failure costs a round-trip, not correctness", () => {
  return (async () => {
    const { fetchImpl, seen } = fakeApi();
    const issuer = issuerWith(fetchImpl, {
      bindingStore: {
        load: async () => {
          throw new Error("cache backend down");
        },
        save: async () => {},
      },
    });
    const binding = await issuer.activate();
    assert.ok(binding, "a failing cache must fall through to activation, not throw");
    assert.equal(seen.activate.length, 1);
  })();
});

test("a cached binding skips the activation round-trip entirely", () => {
  return (async () => {
    const { fetchImpl, seen, keySet } = fakeApi();
    // Prime a store as a previous run would have left it.
    const saved: Record<string, unknown> = {};
    const warm = issuerWith(fetchImpl, {
      bindingStore: {
        load: async () => null,
        save: async (v: Record<string, unknown>) => {
          Object.assign(saved, v);
        },
      },
    });
    await warm.activate();
    assert.equal(seen.activate.length, 1);
    assert.ok(saved.binding, "activation must populate the store");

    // A new process finds the cache warm: no second activation.
    const cold = issuerWith(fetchImpl, {
      bindingStore: { load: async () => saved, save: async () => {} },
    });
    await cold.activate();
    assert.equal(seen.activate.length, 1, "a warm cache must not re-activate");
    assert.equal((saved.binding as { level1_binding: { holder_key_set_root: string } }).level1_binding.holder_key_set_root, keySet.root);
  })();
});

// ---------------------------------------------------------------------------
// A malformed 200 is refused, and nothing is cached or persisted.
//
// The response must be a JSON object, and
// `level1_binding`, `level1_signature`, `holder_id` and `pool_id` must each carry
// a value (absent, null, "", 0, false, {} and [] all count as missing).
// ---------------------------------------------------------------------------

function storeSpy() {
  const saved: unknown[] = [];
  return {
    saved,
    store: { load: async () => null, save: async (v: unknown) => void saved.push(v) },
  };
}

async function assertRefusedAndNothingKept(
  activateBody: (body: Record<string, unknown>) => unknown,
  message: RegExp,
) {
  const { fetchImpl, seen } = fakeApi({ activateBody });
  const { saved, store } = storeSpy();
  const issuer = issuerWith(fetchImpl, { bindingStore: store, holderId: "configured" });
  await assert.rejects(
    () => issuer.activate(),
    (err: unknown) => {
      assert.ok(err instanceof CertcryptNodeError, "a typed error, not a TypeError later");
      assert.match(err.message, message);
      assert.equal(err.status, null, "a 200 that is not an activation has no HTTP failure status");
      return true;
    },
  );
  assert.equal(issuer.binding(), null, "nothing cached in memory");
  assert.deepEqual(saved, [], "nothing persisted");
  // Nothing half-adopted: the configured holder is untouched, and the next call
  // goes back to the network instead of reusing a broken binding.
  assert.equal((issuer as unknown as { holderId?: string }).holderId, "configured");
  await assert.rejects(() => issuer.activate(), CertcryptNodeError);
  assert.equal(seen.activate.length, 2);
}

for (const field of ["level1_binding", "level1_signature", "holder_id", "pool_id"]) {
  test(`a 200 without ${field} is refused`, () =>
    assertRefusedAndNothingKept((b) => {
      const { [field]: _dropped, ...rest } = b;
      return rest;
    }, new RegExp(`^activate returned no ${field}$`)));

  for (const [label, value] of [
    ["null", null],
    ["empty string", ""],
    ["empty object", {}],
    ["empty array", []],
    ["false", false],
    ["zero", 0],
  ] as const) {
    test(`a 200 with ${field} = ${label} is refused`, () =>
      assertRefusedAndNothingKept(
        (b) => ({ ...b, [field]: value }),
        new RegExp(`^activate returned no ${field}$`),
      ));
  }
}

test("every missing field is named, in a fixed order", () =>
  assertRefusedAndNothingKept(
    () => ({ status: "redeemed" }),
    /^activate returned no level1_binding, level1_signature, holder_id, pool_id$/,
  ));

for (const [label, raw] of [
  ["not JSON", "<html>bad gateway</html>"],
  ["a JSON array", "[]"],
  ["JSON null", "null"],
  ["a JSON string", '"ok"'],
  ["empty", ""],
] as const) {
  test(`a 200 whose body is ${label} is refused`, () =>
    assertRefusedAndNothingKept(() => raw, /^activate returned no JSON object$/));
}

test("the idempotent replay status is a success, and the binding is the server's", () => {
  return (async () => {
    const { fetchImpl } = fakeApi({
      activateBody: (b) => ({ ...b, status: "already_consumed_same_root" }),
    });
    const issuer = issuerWith(fetchImpl, { holderId: "configured" });
    const binding = await issuer.activate();
    assert.equal(
      (binding.level1_binding as { authorized_role: string }).authorized_role,
      "issuer",
    );
    assert.equal((issuer as unknown as { holderId?: string }).holderId, "holder-1");
  })();
});

// ---------------------------------------------------------------------------
// Wrong types and unrecognized statuses.
//
// After presence, each field is checked for the shape the SDK later relies on:
// `level1_binding` an object, `level1_signature` a composite signature (`alg`,
// `mode`, one or more components each with `alg` and `sig_b64`), `holder_id`
// and `pool_id` strings. Then `status` must be `redeemed` or `already_consumed_same_root`.
// ---------------------------------------------------------------------------

const SIG_COMPONENT = { alg: "ML-DSA-65", sig_b64: "c2ln" };

for (const [field, value] of [
  ["level1_binding", "a string"],
  ["level1_binding", ["a", "list"]],
  ["level1_binding", 7],
  ["level1_signature", "c2ln"],
  ["level1_signature", ["c2ln"]],
  ["level1_signature", { alg: "composite", mode: "AND", signatures: [] }],
  ["level1_signature", { alg: "composite", mode: "AND", signatures: ["c2ln"] }],
  ["level1_signature", { mode: "AND", signatures: [SIG_COMPONENT] }],
  ["level1_signature", { alg: "composite", signatures: [SIG_COMPONENT] }],
  ["level1_signature", { alg: "composite", mode: "AND" }],
  ["level1_signature", { alg: "composite", mode: "AND", signatures: [{ alg: "ML-DSA-65" }] }],
  ["level1_signature", { alg: "composite", mode: "AND", signatures: [{ sig_b64: "c2ln" }] }],
  ["level1_signature", { alg: "composite", mode: "AND", signatures: [{ ...SIG_COMPONENT, low_s: "yes" }] }],
  ["level1_signature", { alg: "composite", mode: "AND", signatures: [{ ...SIG_COMPONENT, encoding: 1 }] }],
  ["holder_id", 7],
  ["holder_id", true],
  ["holder_id", { id: "h" }],
  ["pool_id", ["pool"]],
] as const) {
  test(`a 200 with ${field} = ${JSON.stringify(value)} is refused as malformed`, () =>
    assertRefusedAndNothingKept(
      (b) => ({ ...b, [field]: value }),
      new RegExp(`^activate returned a malformed ${field}$`),
    ));
}

test("every malformed field is named, in a fixed order", () =>
  assertRefusedAndNothingKept(
    (b) => ({
      ...b,
      level1_binding: "x",
      level1_signature: "y",
      holder_id: 1,
      pool_id: 2,
    }),
    /^activate returned a malformed level1_binding, level1_signature, holder_id, pool_id$/,
  ));

for (const status of [null, "", "rejected", "already_consumed", "REDEEMED", 1, ["redeemed"]]) {
  test(`a 200 with status ${JSON.stringify(status)} is refused`, () =>
    assertRefusedAndNothingKept(
      (b) => ({ ...b, status }),
      /^activate returned an unrecognized status$/,
    ));
}

test("a 200 without a status is refused", () =>
  assertRefusedAndNothingKept(
    (b) => {
      const { status: _dropped, ...rest } = b;
      return rest;
    },
    /^activate returned an unrecognized status$/,
  ));

test("a full composite signature with its optional members is accepted", async () => {
  const signature = {
    alg: "certcrypt-composite-p256-mldsa65-v1",
    mode: "AND",
    signatures: [
      { alg: "ECDSA-P256-SHA3-256", encoding: "raw-rs-64", low_s: true, sig_b64: "cg==" },
      { alg: "ML-DSA-65", sig_b64: "cQ==" },
    ],
  };
  const { fetchImpl } = fakeApi({ activateBody: (b) => ({ ...b, level1_signature: signature }) });
  const binding = await issuerWith(fetchImpl).activate();
  assert.deepEqual(binding.level1_signature, signature);
});

