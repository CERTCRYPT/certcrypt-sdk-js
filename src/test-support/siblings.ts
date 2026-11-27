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
 * Locating the sibling checkouts the byte-parity tests need.
 *
 * Two kinds of test live in this repo. Most are self-contained. But the ones that
 * matter most — the byte-parity tests — assert that this SDK produces EXACTLY the
 * bytes the published conformance vectors pin, and that the verifier toolkit accepts
 * what the SDK signs. Those cannot be self-contained: checking parity against a
 * vector means having the vector, and checking that a verifier accepts a signature
 * means having the verifier.
 *
 * So they read from sibling checkouts, laid out next to this one:
 *
 *   your-workspace/
 *     certcrypt-sdk-js/                  <- this repo
 *     certcrypt-conformance/             <- the published vectors
 *     certcrypt-verifier-toolkit-js/     <- built (npm run build)
 *
 * WHEN A SIBLING IS ABSENT the affected tests FAIL, naming what is missing. That is
 * the default, and the default is the point: a skipped test reports no failure, so a
 * run without the siblings would end in `fail 0` having never checked parity at all
 * — the one property these tests exist to prove. Making rigor opt-in gets it
 * backward, because whoever forgets the flag is precisely whoever needed it.
 *
 * Set `CERTCRYPT_ALLOW_MISSING_CONFORMANCE=1` to skip instead. It is for a
 * contributor working on this repo alone who knows the parity half did not run; it
 * is never for CI, and never for a release check.
 *
 * ## The contract VERSION is checked too
 *
 * Requiring the contract to be PRESENT is not enough. Two implementations can each
 * build green against a DIFFERENT version of it and diverge anyway; what keeps them
 * in step is agreeing on the same `VERSION`. So a checkout whose VERSION is not
 * {@link EXPECTED_CONTRACT_VERSION} fails, and raising that constant is the
 * deliberate act of adopting a new contract.
 *
 * Resolution is from `import.meta.url`, never from cwd, so `npm test` works from any
 * directory. The `../../..` walk is out of `dist/src/<dir>/` to the workspace root.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Workspace root: the directory holding this checkout and its siblings. */
function workspaceRoot(fromFileUrl: string): string {
  // dist/src/<subdir>/<file>.js -> up 4 = this repo -> up 1 more = the workspace.
  return resolve(dirname(fileURLToPath(fromFileUrl)), "../../../..");
}

/** Absolute path to a sibling checkout, resolved from the calling test's location. */
export function siblingPath(fromFileUrl: string, ...segments: string[]): string {
  return resolve(workspaceRoot(fromFileUrl), ...segments);
}

/**
 * The conformance contract version this repository is held to.
 *
 * Bump it together with the checkout, never ahead of it: the value is a claim about
 * what this code has actually been run against.
 */
export const EXPECTED_CONTRACT_VERSION = "1.0.0";

/** Opt OUT of requiring a sibling. Absent, a missing one is a failure. */
const ENV_ALLOW_MISSING = "CERTCRYPT_ALLOW_MISSING_CONFORMANCE";

/**
 * Opt out of the version equality check while still requiring the contract, for the
 * one legitimate case: trying a newer suite before adopting it.
 */
const ENV_ALLOW_VERSION_MISMATCH = "CERTCRYPT_ALLOW_CONFORMANCE_VERSION_MISMATCH";

/** Guards against repeating the same version warning once per calling test. */
let versionChecked = false;

/**
 * Throw when the conformance checkout is present but is the WRONG version.
 *
 * A no-op when the contract is absent: that case belongs to {@link missingSibling},
 * which can name the specific path that was missing.
 */
function assertContractVersion(fromFileUrl: string): void {
  if (versionChecked) return;
  const versionFile = siblingPath(fromFileUrl, "certcrypt-conformance", "VERSION");
  if (!existsSync(versionFile)) return;
  const found = readFileSync(versionFile, "utf-8").trim();
  if (found === EXPECTED_CONTRACT_VERSION) {
    versionChecked = true;
    return;
  }
  if (process.env[ENV_ALLOW_VERSION_MISMATCH] === "1") {
    console.warn(
      `WARNING: conformance contract is ${found}, this repo claims ` +
        `${EXPECTED_CONTRACT_VERSION}, and ${ENV_ALLOW_VERSION_MISMATCH}=1 — ` +
        `this run does NOT back a conformance claim`
    );
    versionChecked = true;
    return;
  }
  throw new Error(
    `conformance contract version mismatch: the checkout is ${found}, this repo is ` +
      `held to ${EXPECTED_CONTRACT_VERSION}. Two implementations that each build green ` +
      `against a different contract version have no agreement between them. Either ` +
      `check out ${EXPECTED_CONTRACT_VERSION}, or adopt ${found} by raising ` +
      `EXPECTED_CONTRACT_VERSION in src/test-support/siblings.ts and re-running. Set ` +
      `${ENV_ALLOW_VERSION_MISMATCH}=1 to explore a bump without adopting it.`
  );
}

/**
 * `undefined` when the required sibling path is present; a skip reason when it is
 * absent AND the opt-out is set — otherwise it throws.
 *
 * Pass straight to `test(name, {skip}, fn)`: node's runner treats `undefined` as
 * "do not skip", so under the opt-out the output tells the reader what to check out
 * rather than what broke.
 */
export function missingSibling(
  fromFileUrl: string,
  repo: string,
  ...segments: string[]
): string | undefined {
  const path = siblingPath(fromFileUrl, repo, ...segments);
  if (existsSync(path)) {
    assertContractVersion(fromFileUrl);
    return undefined;
  }
  const hint =
    repo === "certcrypt-verifier-toolkit-js"
      ? `check it out next to this repo and build it (npm run build)`
      : `check it out next to this repo`;
  const reason = `requires the ${repo} sibling checkout — ${hint}. Looked for: ${path}`;
  // Failing is the default. Throwing surfaces before any assertion runs, so the
  // message is the first thing in the output rather than a line in a skip list.
  if (process.env[ENV_ALLOW_MISSING] !== "1") {
    throw new Error(
      `the conformance contract is required, so this cannot be skipped: ${reason}\n` +
        `Set ${ENV_ALLOW_MISSING}=1 to acknowledge running without it.`
    );
  }
  return reason;
}
