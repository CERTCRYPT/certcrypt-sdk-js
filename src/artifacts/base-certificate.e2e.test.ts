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
 * End-to-end: the SDK mints a signed base_certificate with a verifiable subject
 * anchor (binary + text), and the verifier-toolkit's full `verify()` accepts it
 * — structure → composite issuer signature → original-material.
 *
 * This is the closed loop the SDK exists for: a certificate the SDK
 * produces, verified against its original material by the public toolkit, with
 * the issuer signature actually checked.
 *
 * The toolkit publishes no `exports` map, so both its compiled `verify()` and its
 * conformance config are imported by path into its `dist/`. It is expected as a sibling
 * checkout, built.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { siblingPath, missingSibling } from "../test-support/siblings.js";
import {
  assembleBaseCertificate,
  generateIssuerKey,
  generateNonceHex,
} from "./base-certificate.js";

const TOOLKIT_DIST = siblingPath(
  import.meta.url,
  "certcrypt-verifier-toolkit-js", "dist", "core"
);
const skip = missingSibling(
  import.meta.url,
  "certcrypt-verifier-toolkit-js", "dist", "core"
);

// TEST_ROOT_FINGERPRINT (the conformance synthetic root); used as anchor.root_id.
const TEST_ROOT_FINGERPRINT =
  "4641cb3850fdfde06875bed9382b2afeb2a108ac48ef32d4e196d456a0059635";

async function loadToolkit(): Promise<{ verify: any; config: any }> {
  // Init the lazy ML-DSA backend before any synchronous verify.
  const mldsa = await import(
    pathToFileURL(resolve(TOOLKIT_DIST, "crypto/ml-dsa.js")).href
  );
  const ok = await mldsa.initMlDsa65();
  if (!ok) throw new Error("toolkit ML-DSA-65 backend unavailable");
  // Install the toolkit's Node filesystem bridge. It is a SIDE-EFFECT module the
  // toolkit's own entry points (and its `--import` test flag) load for it; loading
  // `verify.js` by absolute path as we do here bypasses those, so without this the
  // toolkit has no way to read a file and every `*_path` input below fails
  // INPUT_COMBINATION_VALID with "no filesystem available in this runtime".
  await import(
    pathToFileURL(resolve(TOOLKIT_DIST, "input/register-node-fs.js")).href
  );
  const verifyMod = await import(
    pathToFileURL(resolve(TOOLKIT_DIST, "verify.js")).href
  );
  // Test profiles live in the toolkit's harness, not in config/default.js —
  // that module exports only getCertcryptConfig(), the production profile.
  const cfgMod = await import(
    pathToFileURL(resolve(TOOLKIT_DIST, "..", "harness", "profiles.js")).href
  );
  // The conformance config (rules/conformance, synthetic root). The toolkit
  // verifies every signature under every config, so the issuer signature is
  // really checked.
  return { verify: verifyMod.verify, config: cfgMod.getConformanceConfig() };
}

/** True iff a check id is NOT among the failed checks (i.e. it passed). */
function passed(result: any, checkId: string): boolean {
  const failed: string[] = result.failed_check_ids ?? [];
  return !failed.includes(checkId);
}

test("SDK-minted cert (binary+text) verifies end-to-end under the toolkit", {skip}, async () => {
  const { verify, config } = await loadToolkit();

  const pdfLike = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x00, 0xff]); // "%PDF-1.7\0\xff"
  const textMaterial = new TextEncoder().encode("Sample agreement.\nClause 1.\n");

  const issuerKey = generateIssuerKey("issuer:e2e-test");
  const minted = assembleBaseCertificate({
    subjects: [
      { profile: "subject.binary/1", material: pdfLike },
      { profile: "subject.text/1", material: textMaterial },
    ],
    nonce_hex: generateNonceHex(),
    issued_at: "2026-07-07T12:00:00Z",
    root_id: TEST_ROOT_FINGERPRINT,
    system_id: "certcrypt",
    rules_version: "rules/conformance",
    issuerKey,
  });

  const dir = mkdtempSync(join(tmpdir(), "certcrypt-e2e-"));
  try {
    const certPath = join(dir, "base-certificate.json");
    writeFileSync(certPath, JSON.stringify(minted.base_certificate));

    // Original-material delivery: subject index → material blob (byte-exact).
    const bin0 = join(dir, "subject-0.bin");
    const txt1 = join(dir, "subject-1.bin");
    writeFileSync(bin0, Buffer.from(pdfLike));
    writeFileSync(txt1, Buffer.from(textMaterial));
    const manifestPath = join(dir, "original-material.json");
    writeFileSync(
      manifestPath,
      JSON.stringify([
        { material_file: "subject-0.bin" },
        { material_file: "subject-1.bin" },
      ])
    );

    const result = verify(
      {
        verification_target_requested: "issued",
        input_mode: "artifact_set",
        base_certificate_path: certPath,
        original_material_path: manifestPath,
      },
      config
    );

    // The composite issuer signature was really checked, and material matched.
    const ctx = () => JSON.stringify(
      { result_code: result.result_code, failed_check_ids: result.failed_check_ids, diagnostics: result.diagnostics },
      null, 1
    );
    assert.ok(passed(result, "BASE_CERTIFICATE_STRUCTURE_VALID"), `structure: ${ctx()}`);
    assert.ok(passed(result, "BASE_CERTIFICATE_AUTHENTIC"), `authentic (composite sig): ${ctx()}`);
    assert.ok(passed(result, "ORIGINAL_MATERIAL_COMPARISON_VALID"), `original-material: ${ctx()}`);
    assert.equal(result.issued_valid, true, `issued_valid: ${ctx()}`);
    assert.equal(result.complete_verification_against_original_material_performed, true);
    assert.equal(result.complete_verification_against_original_material_passed, true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("tampered material fails original-material (ISSUED_INVALID)", {skip}, async () => {
  const { verify, config } = await loadToolkit();
  const issuerKey = generateIssuerKey("issuer:e2e-tamper");
  const minted = assembleBaseCertificate({
    subjects: [{ profile: "subject.text/1", material: new TextEncoder().encode("original\n") }],
    nonce_hex: generateNonceHex(),
    issued_at: "2026-07-07T12:00:00Z",
    root_id: TEST_ROOT_FINGERPRINT,
    system_id: "certcrypt",
    rules_version: "rules/conformance",
    issuerKey,
  });

  const dir = mkdtempSync(join(tmpdir(), "certcrypt-e2e-tamper-"));
  try {
    const certPath = join(dir, "base-certificate.json");
    writeFileSync(certPath, JSON.stringify(minted.base_certificate));
    // Deliver DIFFERENT material than what was committed.
    writeFileSync(join(dir, "subject-0.bin"), Buffer.from(new TextEncoder().encode("tampered\n")));
    const manifestPath = join(dir, "original-material.json");
    writeFileSync(manifestPath, JSON.stringify([{ material_file: "subject-0.bin" }]));

    const result = verify(
      {
        verification_target_requested: "issued",
        input_mode: "artifact_set",
        base_certificate_path: certPath,
        original_material_path: manifestPath,
      },
      config
    );
    // Structure + signature still pass (the cert is authentic); material fails.
    assert.ok(passed(result, "BASE_CERTIFICATE_AUTHENTIC"));
    assert.ok(!passed(result, "ORIGINAL_MATERIAL_COMPARISON_VALID"));
    assert.equal(result.complete_verification_against_original_material_passed, false);
    assert.equal(result.result_code, "ISSUED_INVALID");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
