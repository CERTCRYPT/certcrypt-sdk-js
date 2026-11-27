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
 * RFC 3339 second-precision UTC timestamp normalization.
 *
 * `Date.prototype.toISOString()` always emits ".000Z" for whole seconds;
 * the canonical form strips zero subseconds. To produce byte-identical
 * canonical bytes we must drop the fractional part. Inputs are required to fall on a whole second (millis === 0);
 * a non-zero millisecond component is rejected rather than silently truncated.
 */
export function toRfc3339Seconds(value: Date | string): string {
  if (typeof value === "string") {
    // Trust a caller-supplied string only if it is already second-precision Z.
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
      throw new Error(
        `timestamp string must be RFC 3339 UTC second precision (…Z, no fractional seconds), got ${JSON.stringify(value)}`
      );
    }
    return value;
  }
  if (Number.isNaN(value.getTime())) {
    throw new Error("timestamp is an invalid Date");
  }
  if (value.getUTCMilliseconds() !== 0) {
    throw new Error(
      "timestamp must fall on a whole second (no sub-second precision is allowed in the canonical bytes)"
    );
  }
  // toISOString() => "2026-05-09T12:00:00.000Z"; strip ".000".
  return value.toISOString().replace(/\.\d{3}Z$/, "Z");
}
