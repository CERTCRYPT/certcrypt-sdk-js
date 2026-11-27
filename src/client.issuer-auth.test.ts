import { test } from "node:test";
import assert from "node:assert/strict";
import { CertcryptNodeClient, issuerAuthMessage, type IssuerAuthRequest } from "./client.js";
import { ZERO_DATA_PROFILE } from "./artifacts/capacity-evidence.js";

// The same vector is asserted by certcrypt-node (auth.rs) and certcrypt-sdk-python:
// three implementations, one message.
test("the issuer proof message matches the shared vector", () => {
  assert.equal(
    issuerAuthMessage("1700000000000.abc", {
      method: "post",
      url: "http://127.0.0.1:4041/v1/issue",
      body: "{}",
    }),
    "certcrypt:issuer-auth:1|1700000000000.abc|127.0.0.1:4041|POST /v1/issue|" +
      "840eb7aa2a9935de63366bacbe9d97e978a859e93dc792a0334de60ed52f8e99",
  );
  // A default port is not part of the host; the query is part of the path.
  assert.equal(
    issuerAuthMessage("1.x", { method: "GET", url: "https://node.example/v1/emissions/unresolved?since=0" }),
    "certcrypt:issuer-auth:1|1.x|node.example|GET /v1/emissions/unresolved?since=0|" +
      "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
  );
  assert.equal(
    issuerAuthMessage("1.x", { method: "GET", url: "https://node.example:443/v1/x" }).split("|")[2],
    "node.example",
  );
});

function recording(statuses: number[]) {
  let calls = 0;
  const auth: string[] = [];
  const asked: IssuerAuthRequest[] = [];
  let proofs = 0;
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const status = statuses[Math.min(calls, statuses.length - 1)];
    calls += 1;
    auth.push(new Headers(init?.headers).get("x-certcrypt-issuer-auth") ?? "");
    const text = status === 200 ? JSON.stringify({ dead: [] }) : "";
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: new Headers(),
      json: async () => JSON.parse(text),
      text: async () => text,
    } as Response;
  }) as typeof fetch;
  const issuerAuthProof = (request: IssuerAuthRequest) => {
    asked.push(request);
    proofs += 1;
    return `proof-${proofs}`;
  };
  const clock = { now: () => 0, sleep: async () => {} };
  return { fetchImpl, issuerAuthProof, clock, auth, asked };
}

// The node accepts a challenge once: a retry that resent the first attempt's
// header would be refused as a replay once that attempt had reached the node.
test("a retried read carries a fresh proof for that request on every attempt", async () => {
  const r = recording([503, 503, 200]);
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    retry: { baseMs: 1, capMs: 1 },
    fetch: r.fetchImpl,
    clock: r.clock,
    issuerAuthProof: r.issuerAuthProof,
  });
  await client.listDeadLetters();
  assert.deepEqual(r.auth, ["proof-1", "proof-2", "proof-3"]);
  for (const req of r.asked) {
    assert.equal(req.method, "GET");
    assert.equal(req.url, "http://node.test/v1/outbox/dead");
  }
});

test("a submit binds its proof to the exact body it sends", async () => {
  const sent: string[] = [];
  const asked: IssuerAuthRequest[] = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    sent.push(init?.body as string);
    const text = JSON.stringify({
      request_id: "R",
      results: [{ operation_id: "op_1", commitment_index: 0, state: { state: "accepted", upstream_operation_id: "U" } }],
    });
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      json: async () => JSON.parse(text),
      text: async () => text,
    } as Response;
  }) as typeof fetch;
  const client = new CertcryptNodeClient({
    baseUrl: "http://node.test",
    fetch: fetchImpl,
    issuerAuthProof: (request) => {
      asked.push(request);
      return "proof";
    },
  });
  await client.issueCommitments([
    { capacity_evidence: { profile: ZERO_DATA_PROFILE }, operative: { holder_id: "h", pool_id: "p" } },
  ] as never);
  assert.equal(asked.length, 1);
  assert.equal(asked[0].method, "POST");
  assert.equal(asked[0].url, "http://node.test/v1/issue");
  assert.equal(asked[0].body, sent[0], "the proof covers the bytes on the wire");
});
