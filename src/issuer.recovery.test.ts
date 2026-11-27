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

import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  emissionHandleFromRecovery,
  type RecoveredHandleFragment,
} from "./issuer.js";

const settled: RecoveredHandleFragment = {
  operationId: "01JQZX3V5K7YB8N2M4P6R8T0AC",
  independenceRef: "a".repeat(64),
  commitmentIndex: 2,
  capacityEvidence: { v: "capacity.evidence/1" },
};

const issuerHeld = {
  baseCertificate: { payload: { system_id: "certcrypt" } },
};

test("recovery joins the two halves into a usable handle", () => {
  const handle = emissionHandleFromRecovery(settled, issuerHeld);
  assert.equal(handle.operationId, settled.operationId);
  assert.equal(handle.independenceRef, settled.independenceRef);
  assert.equal(handle.commitmentIndex, 2);
  assert.deepEqual(handle.capacityEvidence, settled.capacityEvidence);
  // The issuer-held half: CERTCRYPT never had these and never returns them.
  assert.deepEqual(handle.baseCertificate, issuerHeld.baseCertificate);
});

test("a commitmentIndex of 0 is a real position, not a missing one", () => {
  // The falsy-zero trap: `index || fallback` would silently rewrite the first
  // leaf of every set.
  const handle = emissionHandleFromRecovery(
    { ...settled, commitmentIndex: 0 },
    issuerHeld
  );
  assert.equal(handle.commitmentIndex, 0);
});

test("a partial fragment is refused rather than given a placeholder index", () => {
  // The one dangerous mistake in recovery. A substituted index yields an
  // inclusion proof that verifies against NOTHING — the index is a position in
  // the Merkle leaf order, and a wrong position is not a near miss.
  assert.throws(
    () => emissionHandleFromRecovery({ ...settled, commitmentIndex: null }, issuerHeld),
    /has not settled|commitmentIndex/
  );
});

test("the refusal explains what to do instead of just failing", () => {
  // An integrator hitting this at 3am needs the next step, not a type error.
  try {
    emissionHandleFromRecovery({ ...settled, commitmentIndex: null }, issuerHeld);
    assert.fail("must throw");
  } catch (e) {
    const msg = String((e as Error).message);
    assert.match(msg, /[Pp]oll/);
    assert.match(msg, /verifies against nothing/);
  }
});

test("collections and upstreamOperationId ride along when supplied", () => {
  const handle = emissionHandleFromRecovery(settled, {
    ...issuerHeld,
    upstreamOperationId: "01JUPSTREAM0000000000000000",
    collections: [
      { subject_index: 0, descriptor: { kind: "collection" }, leaf_hashes: ["ab"] },
    ] as never,
  });
  assert.equal(handle.upstreamOperationId, "01JUPSTREAM0000000000000000");
  assert.equal(handle.collections?.length, 1);
});

test("recovery never invents the issuer-held half", () => {
  // The fragment carries four fields; the other three come from the caller. If
  // the caller has no certificate, the handle cannot be rebuilt — and that is
  // zero-data working, not a gap to paper over.
  const handle = emissionHandleFromRecovery(settled, issuerHeld);
  const fragmentKeys = Object.keys(settled);
  assert.ok(!fragmentKeys.includes("baseCertificate"));
  assert.ok(!fragmentKeys.includes("collections"));
  // ...and they are present on the result only because the caller supplied them.
  assert.ok(handle.baseCertificate);
  assert.equal(handle.collections, undefined);
});
