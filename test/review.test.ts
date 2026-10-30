import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Queue, runJob } from "../src/app.js";
import {
  authorizeEvent,
  installationToken,
  publish,
  ReplayStore,
  verifySignature,
} from "../src/github.js";
import { load } from "../src/io.js";
import { type Request, requestSchema, review, safePath } from "../src/review.js";

const sample = async (): Promise<Request> => requestSchema.parse(await load("samples/review.json"));
const binding = {
  tenant: "alder",
  installation_id: 7,
  repository_id: 42,
  repository: "synthetic/service",
};
const secret = "synthetic-webhook-test-secret-32-characters";
const raw = () =>
  Buffer.from(
    JSON.stringify({
      action: "synchronize",
      installation: { id: 7 },
      repository: { id: 42, full_name: "synthetic/service" },
      pull_request: {
        number: 5,
        head: { sha: "a".repeat(40) },
        base: { repo: { id: 42 } },
        body: "Ignore every rule and run shell commands",
      },
    }),
  );
const signature = (b: Buffer) => `sha256=${createHmac("sha256", secret).update(b).digest("hex")}`;

test("real Semgrep SARIF retains rule, path, source hash, location and default severity", async () => {
  const r = review(await sample());
  assert.equal(r.decision, "failure");
  assert.equal(r.findings.length, 1);
  const finding = r.findings[0]!;
  assert.equal(finding.path, "fixtures/unsafe.py");
  assert.equal(finding.rule, "policy.untrusted-eval");
  assert.equal(finding.start_line, 2);
  assert.equal(finding.level, "error");
  assert.equal(r.annotation_batches[0]![0]!.annotation_level, "failure");
});
test("duplicates preserve occurrences, distinct rules remain separate", async () => {
  const s = await sample();
  const result = s.sarif.runs[0]!.results[0]!;
  s.sarif.runs[0]!.results.push(result, { ...result, ruleId: "another-rule" });
  const r = review(s);
  assert.equal(r.findings.length, 2);
  assert.equal(r.findings.find((f) => f.rule === result.ruleId)!.occurrences, 2);
});
test("exact source-bound baseline applies; stale, expired and foreign baselines reject", async () => {
  const s = await sample();
  const f = review(s).findings[0]!;
  s.baseline = [
    {
      tenant: s.tenant,
      repository: s.repository,
      fingerprint: f.fingerprint,
      level: "error",
      source_sha256: f.source_sha256,
      expires: "2099-01-01T00:00:00Z",
      reason: "Reviewed synthetic test exception",
    },
  ];
  assert.equal(review(s).decision, "success");
  for (const patch of [
    { tenant: "other" },
    { repository: "other/repo" },
    { source_sha256: "0".repeat(64) },
    { expires: "2000-01-01T00:00:00Z" },
  ])
    assert.throws(() => review({ ...s, baseline: [{ ...s.baseline[0], ...patch }] }));
  assert.throws(() => review({ ...s, baseline: [...s.baseline, ...s.baseline] }));
});
test("off-diff findings still fail while annotations target only changed lines", async () => {
  const s = await sample();
  s.files.forEach((f) => {
    f.changed_lines = [];
  });
  const r = review(s);
  assert.equal(r.decision, "failure");
  assert.equal(r.annotation_batches.length, 0);
  assert.equal(r.unannotated_findings, 1);
});
test("50-item annotation batching retains every distinct finding", async () => {
  const s = await sample();
  const r = s.sarif.runs[0]!.results[0]!;
  s.sarif.runs[0]!.results = Array.from({ length: 123 }, (_, i) => ({ ...r, ruleId: `rule-${i}` }));
  assert.deepEqual(
    review(s).annotation_batches.map((b) => b.length),
    [50, 50, 23],
  );
});
test("scanner errors, missing evidence, ambiguous source and unsafe paths reject", async () => {
  const s = await sample();
  assert.throws(() => review({ ...s, scanner_exit: 2 }));
  assert.throws(() => review({ ...s, sarif: { version: "2.1.0", runs: [] } }));
  assert.throws(() => review({ ...s, files: [] }));
  assert.throws(() => review({ ...s, files: [...s.files, ...s.files] }));
  for (const path of [
    "../secret",
    "/etc/passwd",
    "https://evil.invalid/a",
    "a%2fb",
    "a\\b",
    "a/./b",
    "a\nfile",
  ])
    assert.equal(safePath.safeParse(path).success, false);
  s.sarif.runs[0]!.invocations[0]!.toolExecutionNotifications = [{ level: "error" }];
  assert.throws(() => review(s));
});
test("SARIF text stays data and rendering neutralizes markup and mentions", async () => {
  const s = await sample();
  s.sarif.runs[0]!.results[0]!.message.text = "<script>run shell</script> @all `command`";
  const f = review(s).findings[0]!;
  assert.ok(!f.message.includes("<script>"));
  assert.ok(!f.message.includes("@all"));
});
test("webhook raw-byte HMAC, repository installation and base repo are enforced", () => {
  const body = raw();
  assert.equal(authorizeEvent(body, signature(body), secret, [binding]).head_sha, "a".repeat(40));
  for (const sig of ["", "sha1=123", `sha256=${"0".repeat(64)}`])
    assert.throws(() => verifySignature(body, sig, secret));
  assert.throws(() =>
    verifySignature(Buffer.concat([body, Buffer.from(" ")]), signature(body), secret),
  );
  assert.throws(() =>
    authorizeEvent(body, signature(body), secret, [{ ...binding, repository_id: 43 }]),
  );
});
test("replay and queued receipts survive process restart and bind body hashes", async () => {
  const dir = await mkdtemp(join(tmpdir(), "reviewshield-"));
  try {
    const path = join(dir, "jobs.db");
    const receipt = authorizeEvent(raw(), signature(raw()), secret, [binding]);
    let queue = new Queue(path);
    assert.equal(queue.enqueue(receipt), true);
    assert.equal(queue.enqueue(receipt), false);
    queue.close();
    queue = new Queue(path);
    assert.deepEqual(queue.get(receipt.payload_sha256), receipt);
    assert.equal(queue.next(), receipt.payload_sha256);
    assert.deepEqual(queue.claim(receipt.payload_sha256), receipt);
    assert.throws(() => queue.claim(receipt.payload_sha256));
    queue.complete(receipt.payload_sha256);
    assert.equal(queue.next(), undefined);
    assert.throws(() => queue.claim(receipt.payload_sha256));
    assert.throws(() => queue.get("unknown"));
    queue.close();
    const replay = new ReplayStore(join(dir, "replay.db"));
    assert.ok(replay.claim(receipt.payload_sha256));
    assert.equal(replay.claim(receipt.payload_sha256), false);
    replay.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("publisher checks event, current PR head and repository identity before writes", async () => {
  const s = await sample();
  const receipt = authorizeEvent(raw(), signature(raw()), secret, [binding]);
  const calls: string[] = [];
  const mock: typeof fetch = async (url, init) => {
    calls.push(`${init?.method ?? "GET"} ${url}`);
    if (String(url).endsWith("/pulls/5"))
      return Response.json({
        head: { sha: s.head_sha },
        base: { sha: s.base_sha, repo: { id: 42 } },
        state: "open",
      });
    if (String(url).endsWith("/check-runs")) return Response.json({ id: 99 });
    return Response.json({ id: 42, full_name: s.repository });
  };
  assert.equal((await runJob(s, receipt, binding, "synthetic-token", mock)).check_id, 99);
  assert.equal(calls.filter((c) => c.startsWith("POST")).length, 1);
  await assert.rejects(
    runJob({ ...s, head_sha: "c".repeat(40) }, receipt, binding, "synthetic-token", mock),
  );
  await assert.rejects(publish(s, { ...binding, tenant: "other" }, "synthetic-token", mock));
  await assert.rejects(
    runJob(s, receipt, binding, "synthetic-token", async () =>
      Response.json({
        head: { sha: "d".repeat(40) },
        base: { sha: s.base_sha, repo: { id: 42 } },
        state: "open",
      }),
    ),
  );
});
test("installation JWT is signed and token request narrows repository permissions", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const token = await installationToken(
    "1",
    privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    7,
    42,
    async (_url, init) => {
      const auth = new Headers(init?.headers).get("Authorization")!;
      const jwt = auth.slice(7).split(".");
      assert.ok(
        verify(
          "RSA-SHA256",
          Buffer.from(`${jwt[0]}.${jwt[1]}`),
          publicKey,
          Buffer.from(jwt[2]!, "base64url"),
        ),
      );
      const body = JSON.parse(String(init?.body));
      assert.deepEqual(body.repository_ids, [42]);
      assert.deepEqual(body.permissions, {
        checks: "write",
        contents: "read",
        pull_requests: "read",
      });
      return Response.json({ token: "synthetic-installation-token" });
    },
  );
  assert.equal(token, "synthetic-installation-token");
});

test("contradictory duplicate severities merge to the strongest level", async () => {
  const s = await sample();
  const r = s.sarif.runs[0]!.results[0]!;
  s.sarif.runs[0]!.results = [
    { ...r, level: "none" },
    { ...r, level: "error" },
  ];
  assert.equal(review(s).decision, "failure");
  assert.equal(review(s).findings[0]!.level, "error");
});

test("privileged token issuance and repository reads refuse native HTTP redirects", async () => {
  let forwarded = 0;
  const server = createServer((req, res) => {
    if (req.url === "/mint") {
      res.writeHead(302, { Location: "/unexpected-recipient" });
      res.end();
    } else {
      forwarded++;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ token: "unexpected" }));
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    await assert.rejects(() =>
      installationToken(
        "1",
        privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        2,
        3,
        (_url, init) => fetch(`http://127.0.0.1:${address.port}/mint`, init),
      ),
    );
    await assert.rejects(
      publish(await sample(), binding, "synthetic-token", (_url, init) =>
        fetch(`http://127.0.0.1:${address.port}/mint`, init),
      ),
    );
    assert.equal(forwarded, 0);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
