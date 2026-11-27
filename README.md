# CERTCRYPT SDK for JavaScript

Official JavaScript/TypeScript SDK for integrating with CERTCRYPT infrastructure to produce certification artifacts that can reach `Independent`.

CERTCRYPT is infrastructure that makes certification independently verifiable under public rules. Selected artifacts can reach `Independent` through `Proof of Independence`, a structural result, so later verification no longer depends on the issuer's live systems.

The issuer remains responsible for issuing the base certificate and controlling the original material. CERTCRYPT does not validate semantic truth, does not decide whether document content is true, and does not custody the original material.

## Install

```sh
npm install @certcrypt/sdk
```

Requires Node.js 20 or newer.

**You will need credentials to issue.** The SDK signs client-side, but an issuer's
key-set root has to be authorized before anything it emits can reach `Independent`.
Get yours at **[console.certcrypt.com](https://console.certcrypt.com)**.

## Core idea

Most digital certificates, records, messages, and decisions remain dependent on the systems that issued them.

That dependency is fragile over time. Systems are migrated, providers change, databases are archived, credentials expire, and institutions reorganize.

CERTCRYPT addresses this by allowing selected certification artifacts to reach `Independent`: a state in which later verification can be evaluated under public rules without relying on the issuer as a live system.

## SDK scope

This repository hosts the issuer-side SDK. It helps issuer systems:

- integrate with CERTCRYPT infrastructure
- produce certification artifacts at issuance
- support selected artifacts reaching `Independent`
- preserve separation between issuer emission and later independent verification

The SDK does not replace the issuer's own certificate issuance logic and does not make claims about the truth, legal validity, or factual correctness of the underlying content.

### The signing key stays with the issuer

The issuer signs its own certificates, client-side, with a key derived from a seed it
holds. CERTCRYPT never receives that seed and never signs on an issuer's behalf.

That has a direct consequence for where this SDK runs: it is **server-side only**. It
requires Node.js 20 or newer, and the issuer seed must never reach a browser bundle —
anyone who obtains it can issue as that issuer.

### The node is a transport

Your issuance goes through a CERTCRYPT node. The SDK activates through it and
hands it your submissions, and asks it for nothing else: no identity proof, no
pinned key, nothing to configure about which node you use.

That is safe because nothing the node relays is taken on its word. The node
cannot forge a certificate — you sign it here, with a key CERTCRYPT never sees —
and what comes back, the `Proof of Independence`, is signed by the CERTCRYPT
System Domain. Whether a node may submit at all is decided by the CERTCRYPT
service, which admits submissions only from nodes whose operator it recognizes.
A node that misbehaves can delay or drop a submission; it cannot alter or invent
what is signed. A dropped submission shows up as an emission that stays
pending past its expected settlement window, which `resolveEmission()` reports
as overdue.

This SDK does not verify the `Proof of Independence` itself. Any verifier checks
it offline with the verifier toolkit, and the proof also records which node
carried the submission.

## Usage

Configuration values come from whoever operates the system domain you issue under.
Keep `CERTCRYPT_ISSUER_KEYSET_SEED` in a secret manager: it is the issuer's
identity, and everything the SDK signs derives from it.

`rulesVersion` carries one value the SDK has to know: the commitment TTL, which is
a public rule of the domain rather than an issuer setting — a verifier requires
`expires_at === issued_at + ttl`. The SDK knows the TTL for the published rules
domains and refuses any other at construction, rather than inventing an expiry
that every conformant verifier would reject. A deployment that runs under its own
rules domain registers it with `registerRulesDomain("rules/...")` before
constructing `Certcrypt`, and passes `commitmentTtlSeconds` with that domain's
value. Registering asserts that the domain forms artifacts exactly as a published
one does; an unregistered domain is still refused.

```js
import { readFileSync } from "node:fs";
import { Certcrypt } from "@certcrypt/sdk";

const certcrypt = new Certcrypt({
  nodeBaseUrl: process.env.CERTCRYPT_NODE_BASE_URL,
  keysetSeed: process.env.CERTCRYPT_ISSUER_KEYSET_SEED,
  integrationKey: process.env.CERTCRYPT_ISSUER_INTEGRATION_KEY,
  poolId: process.env.CERTCRYPT_POOL_ID,
  rulesVersion: process.env.CERTCRYPT_RULES_VERSION,
  systemRootFingerprint: process.env.CERTCRYPT_SYSTEM_ROOT_FINGERPRINT,
  systemId: process.env.CERTCRYPT_SYSTEM_ID,
});

// Certify the material itself. The SDK derives the signing key from the seed,
// mints a signed base certificate, and submits it toward `Independent`.
const material = readFileSync("invoice-2026-0041.pdf");

const { handle } = await certcrypt.issue({
  subjects: [{ profile: "subject.binary/1", material }],
});

// Persist the handle — it identifies the operation and lets you finish the job later, even
// after a restart, without re-emitting.
saveSomewhere(handle);

// Later: assemble the package a third party can verify offline, without contacting
// you. Settlement is not instantaneous, so this reports where the emission is —
// `pending` means retry later, never that anything is wrong.
// The package records this instance's `rulesVersion` and `systemId`; pass
// `verificationContext` only to record something else.
const resolution = await certcrypt.resolveEmission(handle);

if (resolution.state === "independent") {
  saveSomewhere(resolution.verificationPackage);
} else if (resolution.state === "pending") {
  // Not settled yet; the handle stays valid.
} else {
  // "rejected" or "expired" — terminal, and `resolution.nodeState` says why.
}
```

### The authorization your issuer needs

Before an issuer can emit, its **operation-key root must be authorized by a system
domain**. That authorization is a `level1_binding` the domain signs over your
key-set root, and it is what a verifier ultimately checks: everything you sign
derives its authority from it. This part is protocol — `capacity.evidence/1` fixes
the binding's exact fields and their order.

**How you obtain it is not.** Each system domain decides that for itself: a portal,
an existing PKI, an offline ceremony, or an automated exchange. The SDK supports
both shapes:

- **You already hold a binding** — pass it as `signedLevel1` (with the `holderId`
  and `poolId` it was issued against). The SDK never asks how you got it.
- **The domain issues one automatically** — pass an `integrationKey` and the SDK
  redeems it on first use.

The second is what CERTCRYPT's own domain does, and it is the shape the example
above uses — issue an integration key from
[console.certcrypt.com](https://console.certcrypt.com), put it in config, and the
SDK does the rest. Its properties, if your domain works that way: there is **no first-run
branch to write** — `keysetSeed` and `integrationKey` are two halves of one boot
credential, provisioned from config and kept. The key-set root is re-derived from
the seed, so re-presenting the same key is an idempotent replay answered with the
same binding. The key is "one-time" only in that its first use binds it to that
root; presenting it with a *different* root is refused, which protects you against
someone else claiming your integration, not against your own restart.

The first `issue()` redeems on the way past, so most integrations call nothing
explicitly. `activate()` exists for when the deploy and the first real certificate
are far apart.

Either way, pass a `bindingStore` to cache the binding and skip a round-trip on
start. It is a cache: omitting it, or having it fail, costs a request and never
correctness.

### Waiting for settlement

`pending` is the normal state of a fresh emission, not a problem: the operation is
waiting to be settled, and settlement batches many operations into one window. How
long that takes depends on the window, and a window can be delayed — by congestion,
or by an incident on the settlement layer itself.

So do not block on it. The handle is a durable reference to the operation: persist it, return to the
caller, and resolve later. A process that restarts, or a different process
altogether, can resolve the same handle without re-emitting.

`resolveEmission` accepts a `wait` option for the in-line case:

```js
const resolution = await certcrypt.resolveEmission(handle, {
  wait: { maxWaitMs: 10 * 60_000 },   // wait up to ten minutes
});
```

#### The node tells you when it expects to settle

You do not have to guess the interval. While an operation is waiting to be settled,
the node reports the settlement window it is assigned to, and the SDK schedules around
it:

```js
const r = await certcrypt.resolveEmission(handle);

if (r.state === "pending") {
  r.settlementWindow;  // { window_profile, window_profile_version, target_close_by, expected_settled_by }
  r.overdue;           // true when expected_settled_by has already passed
}
```

With `wait`, the SDK uses that estimate instead of polling blindly. It checks twice
before calling the operation overdue: once 60 % of the way from `target_close_by` to
`expected_settled_by`, where most settlements have already landed, and once at
`expected_settled_by` plus one second for clock skew. Each check is pushed back by a
random 0–1 s so that the operations of one window do not all ask at the same instant.
When there is no estimate — or the operation is already overdue — it falls back to
exponential backoff with a cap.

`target_close_by` is the moment the **window closes**, not the moment the package is
ready: anchoring and chain finality add more after it. `expected_settled_by` is the
operator's estimate of when that settlement is anchored and final, so that a read can
return a terminal state; it is never earlier than `target_close_by`, and it is present
exactly when `target_close_by` is. Both are operational estimates, not deadlines and
not a promise of when the operation becomes Independent. When the node reports only
`target_close_by`, the SDK sleeps until it plus three seconds and reports `overdue`
once it has passed.

#### Knowing it is still alive

A wait that sleeps for minutes looks exactly like a hang. Pass `onProgress` to report
it — every tick carries a ready-made `message`, so logging it is one line:

```js
await certcrypt.resolveEmission(handle, {
  wait: {
    maxWaitMs: 10 * 60_000,
    onProgress: (p) => log.info(p.message),
    // "still processing after 45s — waiting for settlement window <profile> to
    //  close (~2026-08-16T12:00:40Z), settlement expected by ~2026-08-16T12:00:55Z;
    //  next check in 22s"
  },
});
```

If you pass no `onProgress` and the SDK is about to sleep for ten seconds or more, or
the window is already overdue, it writes that same line to the console
(`console.info`) rather than going quiet. An exception thrown by `onProgress` is
swallowed: reporting never breaks the wait. An operation running
late says so explicitly (`overdue`), which is what a stalled settlement layer actually
looks like from the outside.

#### Wait options

| option | meaning |
| --- | --- |
| `maxWaitMs` | wall-clock bound on the whole wait — usually the only one you need. Under `"auto"` it defaults to 15 minutes, so an omitted value bounds the wait rather than blocking forever; under `"fixed"` only the attempt count bounds the wait unless you set it |
| `strategy` | `"auto"` (default): use the window estimate, else backoff. `"fixed"`: poll every `intervalMs` |
| `backoffBaseMs` / `backoffCapMs` | backoff shape when there is no estimate (defaults 1 s / 30 s) |
| `onProgress` | called before each sleep with a `WaitProgress`: a ready-to-log `message`, plus `attempt`, `nodeState`, `nextCheckInMs`, `elapsedMs`, `overdue`, and — when the node reports them — `window` and `settlement` |
| `intervalMs` / `maxAttempts` | fixed-interval polling: a poll every `intervalMs` (default 1 s), at most `maxAttempts` polls (default 60) |

Passing `intervalMs` or `maxAttempts` selects `"fixed"` unless you also pass
`strategy`. Prefer `maxWaitMs`: an attempt count only means something once you also
know the interval.

When the wait ends without a terminal state, `waitForOperation` throws a
`CertcryptNodeError` saying the operation "did not reach a terminal state", with the
last state it saw. `resolveEmission` does not throw for that: it reports `pending`,
because the handle is still good.

#### Timeouts and retries

Every request to the node is bounded at 30 seconds. A submit and every read
(`getOperation`, `getEmissionByCommitment`, `listUnresolvedEmissions`,
`listDeadLetters`) are retried under the transport-retry policy:
a connection that fails or times out, and a 408, 425, 429 or 5xx, are retried until
the time budget runs out, and a `Retry-After` on 503 or 429 is waited out without
counting as an attempt. A submit keeps the same `request_id` on every attempt, so a
2xx answer whose body is not JSON is retried safely too. Tune it with `retry`:

| option | meaning |
| --- | --- |
| `maxElapsedMs` | total time budget from the first attempt (default 120 s) |
| `maxAttempts` | counted attempts, the first included (default: no limit; 1 disables retry) |
| `baseMs` / `capMs` | backoff shape: attempt n waits a random draw under `baseMs × 2^(n−1)`, capped at `capMs` (defaults 200 ms / 30 s) |

`health()` is one request, never retried, and reports `false` rather than throwing
when the node does not answer.

#### What the window is — and what it is not

The window is **operational information from the operator**, in the same family as the
`settlement_preferences` you send on the way in. It is not part of the protocol:

- it never enters the submission set, the proof, or anything a verifier evaluates;
- the verifier never reads the profile catalog, and a conforming third-party
  implementation reaches Independent without it.

**What is portable, and what is not.** The *shape* is generic and any implementation
can use it: an optional `{ window_profile, window_profile_version, target_close_by, expected_settled_by }`,
plus a scheduler that waits for the timestamp or falls back to backoff. A node that
sends nothing is fully supported — the SDK just backs off, and that path is covered by
tests.

The *values* belong to the rules domain. The profiles a domain admits, and its
default, are published in its public rules (for `rules/2026-01`, section 15), and
they are versioned: a later rules domain can admit a different set. A name is
something to elect on the way in with `settlementPreferences`, not something to
time a wait on. So:

```js
// Fine: schedule on the timestamp.
const w = r.settlementWindow;
const at = w?.expected_settled_by ?? w?.target_close_by;
if (at) scheduleRetryAt(at);

// Fragile: the name is a versioned value of the rules domain — not a timing contract.
if (r.settlementWindow?.window_profile === "some_profile_name") { /* … */ }
```

Use `expected_settled_by` (or `target_close_by` when it is absent) for timing and
`overdue` for "is it late". Treat
`window_profile` as an opaque label for logs and support, and pin nothing to it.

It is also deliberately **free of any cost figure**. There is no amount, no capacity
number, no receipt line and no billing multiplier in it, and none will be added. In
the clear on every response, an operation's cost would let an issuer's operations be
correlated over time — and restricting it to "only your own issuer" would not help,
because once such a value travels in a response it lands in logs and billing
records. The quantity an emission actually consumed is carried in the
`settlement_material` that the `independence_proof` binds — that is the
authoritative figure. Your own costs stay available to you, authenticated and off
the emission path — on CERTCRYPT that is
[console.certcrypt.com](https://console.certcrypt.com).

Knowing that a window is running late reveals nothing about who issued into it.

A certificate can commit to several subjects at once — pass more than one, and note
that the order is significant. Keep the original material: reaching `Independent`
does not need it, but a verifier who compares the material against the commitment
needs those exact bytes.

### Certifying text an application produced

Not everything worth certifying is a file. A consent record, an audit entry, a
decision an application recorded — anything your app can serialize deterministically
is a subject. Use `subject.text/1` and it is canonicalized before being committed to:
line endings are normalized to CRLF and the trailing CRLF run collapses to exactly one, so
the same logical text certifies identically whether it was written on Windows, Linux
or macOS.

```js
// A consent record, exactly as your application stored it.
const record = [
  "consent.v1",
  "user: 4f9c2a71-3e8d-4b16-9a02-7c1d5e8f0b34",
  "scope: analytics,marketing",
  "granted_at: 2026-08-12T09:41:00Z",
  "policy: privacy-notice-2026-06",
].join("\n");

const { handle } = await certcrypt.issue({
  subjects: [{ profile: "subject.text/1", material: new TextEncoder().encode(record) }],
});
```

Two things worth getting right, because a verifier who compares the material
recomputes the commitment from the bytes you certified:

- **Serialize deterministically.** Build the text the same way every time. Iterating
  an object's keys in whatever order they happen to come out will produce a different
  commitment for the same logical record.
- **Store what you certified**, not just the fields it came from. Reassembling the
  text later from a database row is how a certificate stops matching its material.

If the record is structured rather than flat text, `subject.collection/1` and
`subject.ai-decision/1` take JSON and canonicalize the *value* (RFC 8785), so key
order stops mattering.

### Handing out one element of a collection

A `subject.collection/1` binds each of its elements individually, so a holder can be
shown that ONE element belongs to the certified set without receiving the rest of it
— or the certificate. What they need is an inclusion proof, and only whoever holds
the certificate can build one: the path is folded from the collection's own leaf
digests.

The SDK exports the primitives, so you never fold the Merkle path by hand:

```js
import {
  collectionLeafHash,
  collectionInclusionProof,
  canonicalBytesForSubject,
  COLLECTION_MERKLE_SCHEME,
} from "@certcrypt/sdk";

// Everything comes from the certificate you already hold (`baseCertificate`),
// plus the element you hand out: its bytes (`leafBytes`) and its position.
const anchor = baseCertificate.payload.anchor;
const collectionSalt = new TextEncoder().encode(anchor.nonce_hex);
const collection = anchor.subjects[subjectIndex].collection;
const leafHashes = collection.leaves.map((l) => l.commitment_digest_hex);

// Find the element by its own salted hash. Its POSITION is the leaf_index — it is
// derived, never declared, so a wrong one simply folds to a different root.
const profile = collection.leaves[leafIndex].profile;
const canonical = canonicalBytesForSubject(profile, leafBytes);
const index = leafHashes.indexOf(collectionLeafHash(collectionSalt, profile, canonical));
if (index === -1) throw new Error("not a declared leaf of this collection");

const proof = {
  proof_version: COLLECTION_MERKLE_SCHEME,
  leaf_index: String(index),
  sibling_hashes: collectionInclusionProof(leafHashes, index),
};

console.log(JSON.stringify(proof, null, 2));
```

`collectionInclusionProof` is the part worth not rewriting: a node that is the lone
right edge of an odd level is promoted unchanged and contributes **no** sibling. Get
that wrong and the path folds to a different root — the proof simply fails to verify,
with nothing to say why. The conformance vectors cover odd cardinalities precisely
because it is the easy mistake.

Send the holder the element, this proof, and the collection's declared `root`,
`declared_cardinality`, leaf `profile` and the anchor's `nonce_hex` (the salt).
Never the rest of the collection. `verifyCollectionInclusion` in the toolkit is what
they run against it — the reference implementation of that check is the public
verification portal.

Nothing here has to be stored at issuance: the certificate carries every leaf digest
and the salt, so any element's proof can be rebuilt whenever it is needed.

## Building from source

```sh
npm install
npm run build
npm run lint     # typecheck, no emit
```

The test suite checks byte-parity against the primitive vectors of
`certcrypt-conformance`. This SDK is not a verifier and returns no
`VerifierResult`, so the verdict fixtures do not apply to it; what it must
reproduce is the bytes, identically to every other implementation. State the
version you ran against when you claim parity — the value in the suite's
`VERSION` at that time. The contract is versioned independently of this package.

The ECDSA P-256 half of every signature is part of those bytes: it is RFC 6979
deterministic (conformance family `ecdsa-p256-deterministic`), so the same key
over the same message always gives the same signature. The ML-DSA-65 half is
hedged, so it differs between runs; both halves verify either way.

Running them expects `certcrypt-conformance` and `certcrypt-verifier-toolkit-js`
as sibling checkouts, already built:

```sh
npm test
```

**A missing sibling is a failure, by default.** A skipped test reports no
failure, so if the tests that need a sibling skipped when it was absent, `fail 0`
could describe a run that never checked parity — including the round-trip that
hands a minted certificate to the verifier. Nothing needs to be switched on:
`npm test` without a sibling fails, naming the path it looked for. Making rigor opt-in gets it backward — whoever forgets the flag is
precisely whoever needed it.

```sh
git clone https://github.com/CERTCRYPT/certcrypt-conformance.git ../certcrypt-conformance
npm test
```

Two escape hatches, both deliberate and neither a default:

| Variable | Effect |
| --- | --- |
| `CERTCRYPT_ALLOW_MISSING_CONFORMANCE=1` | Skip instead of failing. For working on this repo alone, knowing the parity half did not run |
| `CERTCRYPT_ALLOW_CONFORMANCE_VERSION_MISMATCH=1` | Run against a contract version this SDK does not claim, to see what a bump would break |

**The contract VERSION is checked too.** Requiring it to be present is not
enough: two implementations can each build green against a different version and
diverge anyway. This SDK is held to `EXPECTED_CONTRACT_VERSION`
(`src/test-support/siblings.ts`), and a checkout that is not that one fails.
Adopting a new contract means raising the constant and re-running.

## CERTCRYPT boundary

- not a claim of factual truth
- not a validator of correctness
- not a custodian of documents
- not blockchain notarization
- not a trust badge

## Boundary of this SDK

- not a replacement for the issuer's own certificate issuance logic
- not a verifier
- not a source of proof validity
- not a document custody library
- not a semantic validator of legal or factual claims

### Trademarks

The Apache-2.0 grant covers copyright, not marks: §6 of the license grants no
permission to use CERTCRYPT trade names, trademarks, service marks or product
names beyond describing the origin of the work.

Stating that your product issues CERTCRYPT certificates, or that it is built on
this SDK, is such a use. Naming your product after CERTCRYPT is not.

The distinction matters more here than in a library that only reads: what this
SDK emits is signed under **your** issuer identity, not CERTCRYPT's. A
certificate minted with it is your act — CERTCRYPT does not review, approve or
countersign it, and presenting one as CERTCRYPT having certified the underlying
material misstates what the artifact says. What the certificate carries is a
commitment that anyone can verify against the public rules, which is the whole
point and is stronger than a badge.

## Documentation

Technical documentation and the public specifications are published at
[docs.certcrypt.com](https://docs.certcrypt.com): the model, the terminology, the
claims boundary, the evaluation model a verifier applies, and the normative
specifications the artifacts in this SDK conform to.

## Links

| Surface | Address |
| --- | --- |
| Website | [certcrypt.com](https://certcrypt.com) |
| Documentation | [docs.certcrypt.com](https://docs.certcrypt.com) |
| Verify an artifact | [verify.certcrypt.dev](https://verify.certcrypt.dev) |
| Blog | [blog.certcrypt.com](https://blog.certcrypt.com) |
| Support | [support.certcrypt.com](https://support.certcrypt.com) |
| Service status | [status.certcrypt.com](https://status.certcrypt.com) |
| Open source | opensource@certcrypt.com |
| Security | security@certcrypt.com — see [`SECURITY.md`](SECURITY.md) |

**The two repositories on the other side of what this SDK emits:**

| Repository | Relationship |
| --- | --- |
| [certcrypt-verifier-toolkit-js](https://github.com/CERTCRYPT/certcrypt-verifier-toolkit-js) | the verifier that evaluates what this SDK mints — this SDK's own suite round-trips its certificates through it, with every signature verified |
| [certcrypt-conformance](https://github.com/CERTCRYPT/certcrypt-conformance) | the public contract both sides are held to; this SDK checks byte parity against its primitive vectors |

Emission and verification are deliberately separate, and the contract in the
middle is data rather than code. That is what makes a certificate this SDK mints
checkable by someone who has neither your systems nor this SDK — which is the
property the whole design exists to produce.

**Verifying what this SDK produces:** [verify.certcrypt.dev](https://verify.certcrypt.dev)
is the public reference implementation of the verifier: no account, no sign-in, and
useful for checking an emission end to end during integration. It runs the toolkit in
your own browser, so original material you choose to compare is read and hashed
locally and never sent anywhere.

## Changelog

Release notes are in [`CHANGELOG.md`](CHANGELOG.md). From 1.0.0 this package
follows semantic versioning: breaking a documented export requires a major
release. Deliberately outside that promise, because it is not API: which verdict a
given artifact receives. A check may be tightened in a minor or a patch, and an
artifact that verified before may then fail — that is a corrected verdict, and the
entry says so.

## License

Copyright 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.
