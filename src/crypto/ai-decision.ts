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

import { randomBytes } from "node:crypto";

import {
  computeSubjectCommitment,
  subjectLocalDigestHex,
  type SubjectInput,
} from "../artifacts/base-certificate.js";
import { canonicalBytesForSubject, SUBJECT_AI_DECISION } from "./canonical-subject.js";

const HEX64 = /^[0-9a-f]{64}$/;

export interface AiDecisionMaterialInput {
  id: string;
  role: string;
  mediaType: string;
  profile: string;
  material: Uint8Array;
  /** Testing only: omit this in production so the SDK generates a fresh nonce. */
  materialNonceHex?: string;
}

export interface AiDecisionPartDescriptor {
  id: string;
  role: string;
  media_type: string;
  profile: string;
  material_nonce_hex: string;
  commitment_digest_hex: string;
}

export interface BuiltAiDecisionPart {
  descriptor: AiDecisionPartDescriptor;
  material: Uint8Array;
}

export interface AiDecisionModel {
  id: string;
  provider: string;
  version?: string;
}

export interface BuildAiDecisionSubjectInput {
  decisionId: string;
  decidedAt: string;
  model: AiDecisionModel;
  observationScope: "client" | "runtime";
  input: AiDecisionMaterialInput[];
  output: AiDecisionMaterialInput[];
  decision: string;
  parameters?: Record<string, string>;
  context?: Record<string, string>;
  startedAt?: string;
  actorId?: string;
  policyRef?: string;
}

export interface AiDecisionRecord {
  profile: typeof SUBJECT_AI_DECISION;
  decision_id: string;
  decided_at: string;
  model: AiDecisionModel;
  observation_scope: "client" | "runtime";
  input: AiDecisionPartDescriptor[];
  output: AiDecisionPartDescriptor[];
  decision: string;
  parameters?: Record<string, string>;
  context?: Record<string, string>;
  started_at?: string;
  actor_id?: string;
  policy_ref?: string;
}

export interface AiDecisionMaterialRecord {
  profile: string;
  material: Uint8Array;
  material_nonce_hex: string;
  commitment_digest_hex: string;
}

export interface BuiltAiDecisionSubject {
  subject: SubjectInput;
  record: AiDecisionRecord;
  /** Original material and opening data, keyed by the part id. Keep this private. */
  materials: Record<string, AiDecisionMaterialRecord>;
}

function generateMaterialNonceHex(): string {
  return randomBytes(32).toString("hex");
}

function assertMaterialNonceHex(value: string): void {
  if (!HEX64.test(value)) {
    throw new Error("materialNonceHex must be 64 lowercase hex characters");
  }
}

/** Build one salted, profile-aware part descriptor without interpreting its material. */
export function buildAiDecisionPart(input: AiDecisionMaterialInput): BuiltAiDecisionPart {
  const material = Uint8Array.from(input.material);
  const materialNonceHex = input.materialNonceHex ?? generateMaterialNonceHex();
  assertMaterialNonceHex(materialNonceHex);
  const localDigest = subjectLocalDigestHex({ profile: input.profile, material });
  return {
    descriptor: {
      id: input.id,
      role: input.role,
      media_type: input.mediaType,
      profile: input.profile,
      material_nonce_hex: materialNonceHex,
      commitment_digest_hex: computeSubjectCommitment(materialNonceHex, localDigest),
    },
    material,
  };
}

/** Build and validate a complete `subject.ai-decision/1` subject. */
export function buildAiDecisionSubject(input: BuildAiDecisionSubjectInput): BuiltAiDecisionSubject {
  const usedNonces = new Set<string>();
  const materials: Record<string, AiDecisionMaterialRecord> = Object.create(null) as Record<
    string,
    AiDecisionMaterialRecord
  >;

  const buildSide = (parts: AiDecisionMaterialInput[]): AiDecisionPartDescriptor[] =>
    parts.map((part) => {
      let materialNonceHex = part.materialNonceHex;
      if (materialNonceHex !== undefined) {
        assertMaterialNonceHex(materialNonceHex);
        if (usedNonces.has(materialNonceHex)) {
          throw new Error("materialNonceHex values must be globally unique across input and output");
        }
      } else {
        do {
          materialNonceHex = generateMaterialNonceHex();
        } while (usedNonces.has(materialNonceHex));
      }
      usedNonces.add(materialNonceHex);
      const built = buildAiDecisionPart({ ...part, materialNonceHex });
      materials[part.id] = {
        profile: part.profile,
        material: built.material,
        material_nonce_hex: materialNonceHex,
        commitment_digest_hex: built.descriptor.commitment_digest_hex,
      };
      return built.descriptor;
    });

  const record: AiDecisionRecord = {
    profile: SUBJECT_AI_DECISION,
    decision_id: input.decisionId,
    decided_at: input.decidedAt,
    model: { ...input.model },
    observation_scope: input.observationScope,
    input: buildSide(input.input),
    output: buildSide(input.output),
    decision: input.decision,
    ...(input.parameters === undefined ? {} : { parameters: { ...input.parameters } }),
    ...(input.context === undefined ? {} : { context: { ...input.context } }),
    ...(input.startedAt === undefined ? {} : { started_at: input.startedAt }),
    ...(input.actorId === undefined ? {} : { actor_id: input.actorId }),
    ...(input.policyRef === undefined ? {} : { policy_ref: input.policyRef }),
  };
  const material = new TextEncoder().encode(JSON.stringify(record));
  canonicalBytesForSubject(SUBJECT_AI_DECISION, material);
  return {
    subject: { profile: SUBJECT_AI_DECISION, material },
    record,
    materials,
  };
}
