// Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");

import assert from "node:assert/strict";
import test from "node:test";

import { computeSubjectCommitment, subjectLocalDigestHex } from "../artifacts/base-certificate.js";
import { buildAiDecisionPart, buildAiDecisionSubject } from "./ai-decision.js";

const NONCE_A = "1".repeat(64);
const NONCE_B = "2".repeat(64);

test("buildAiDecisionPart applies the CCCP subject commitment formula", () => {
  const material = new TextEncoder().encode("approve\n");
  const built = buildAiDecisionPart({
    id: "prompt",
    role: "user",
    mediaType: "text/plain",
    profile: "subject.text/1",
    material,
    materialNonceHex: NONCE_A,
  });
  assert.deepEqual(built.descriptor, {
    id: "prompt",
    role: "user",
    media_type: "text/plain",
    profile: "subject.text/1",
    material_nonce_hex: NONCE_A,
    commitment_digest_hex: computeSubjectCommitment(
      NONCE_A,
      subjectLocalDigestHex({ profile: "subject.text/1", material }),
    ),
  });
});

test("buildAiDecisionSubject returns an issuance subject and private opening material", () => {
  const built = buildAiDecisionSubject({
    decisionId: "decision-1",
    decidedAt: "2026-08-16T12:00:00.000Z",
    model: { id: "model-1", provider: "provider-1", version: "2026-08" },
    observationScope: "client",
    input: [{
      id: "prompt",
      role: "user",
      mediaType: "text/plain",
      profile: "subject.text/1",
      material: new TextEncoder().encode("Should this request be approved?"),
      materialNonceHex: NONCE_A,
    }],
    output: [{
      id: "answer",
      role: "assistant",
      mediaType: "application/json",
      profile: "subject.binary/1",
      material: new TextEncoder().encode('{"decision":"approved"}'),
      materialNonceHex: NONCE_B,
    }],
    decision: "approved",
    parameters: { temperature: "0" },
  });

  assert.equal(built.subject.profile, "subject.ai-decision/1");
  assert.ok(built.subject.material);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(built.subject.material)), built.record);
  assert.deepEqual(Object.keys(built.materials), ["prompt", "answer"]);
  assert.equal(built.materials.prompt.material_nonce_hex, NONCE_A);
  assert.equal(built.materials.answer.material_nonce_hex, NONCE_B);
  assert.notEqual(
    built.record.input[0].commitment_digest_hex,
    built.record.output[0].commitment_digest_hex,
  );
});

test("buildAiDecisionSubject generates independent nonces and refuses reuse", () => {
  const base = {
    decisionId: "decision-1",
    decidedAt: "2026-08-16T12:00:00.000Z",
    model: { id: "model-1", provider: "provider-1" },
    observationScope: "runtime" as const,
    decision: "complete",
  };
  const material = new TextEncoder().encode("same");
  const built = buildAiDecisionSubject({
    ...base,
    input: [{ id: "prompt", role: "user", mediaType: "text/plain", profile: "subject.text/1", material }],
    output: [{ id: "answer", role: "assistant", mediaType: "text/plain", profile: "subject.text/1", material }],
  });
  assert.match(built.record.input[0].material_nonce_hex, /^[0-9a-f]{64}$/);
  assert.match(built.record.output[0].material_nonce_hex, /^[0-9a-f]{64}$/);
  assert.notEqual(built.record.input[0].material_nonce_hex, built.record.output[0].material_nonce_hex);

  assert.throws(
    () => buildAiDecisionSubject({
      ...base,
      input: [{ id: "prompt", role: "user", mediaType: "text/plain", profile: "subject.text/1", material, materialNonceHex: NONCE_A }],
      output: [{ id: "answer", role: "assistant", mediaType: "text/plain", profile: "subject.text/1", material, materialNonceHex: NONCE_A }],
    }),
    /globally unique/,
  );
});
