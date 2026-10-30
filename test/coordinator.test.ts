import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { type Receipt, runJob } from "../src/app.js";
import { changedLines, coordinate, type ScanWorker } from "../src/coordinator.js";
import type { Binding } from "../src/github.js";
import { digest } from "../src/io.js";
import { review } from "../src/review.js";

const binding: Binding = {
  tenant: "alder",
  installation_id: 7,
  repository_id: 42,
  repository: "synthetic/service",
};
const receipt: Receipt = {
  ...binding,
  head_sha: "a".repeat(40),
  pr: 5,
  payload_sha256: "c".repeat(64),
};
const content = Buffer.from("def example(value):\n    return eval(value)\n");
const blobSha = createHash("sha1").update(`blob ${content.length}\0`).update(content).digest("hex");
const change = {
  filename: "nested/source.py",
  sha: blobSha,
  status: "added" as const,
  additions: 2,
  deletions: 0,
  patch: "@@ -0,0 +1,2 @@\n+def example(value):\n+    return eval(value)",
};
const pr = {
  state: "open",
  changed_files: 1,
  head: { sha: receipt.head_sha },
  base: { sha: "b".repeat(40), repo: { id: 42 } },
};
const blob = {
  sha: blobSha,
  encoding: "base64",
  size: content.length,
  content: content.toString("base64"),
};
const native = () => ({
  scope: "configured-python-rules",
  files: { "nested/source.py": digest(content) },
  scanner_exit: 0,
  coverage: { expected: ["nested/source.py"], native_scanned: ["nested/source.py"], errors: [] },
  sarif: {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Semgrep", rules: [{ id: "untrusted-eval" }] } },
        invocations: [{ executionSuccessful: true }],
        results: [
          {
            ruleId: "untrusted-eval",
            level: "error",
            message: { text: "Untrusted input reaches eval" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "nested/source.py" },
                  region: { startLine: 2 },
                },
              },
            ],
          },
        ],
      },
    ],
  },
});
function api(
  overrides: { pr?: unknown; files?: unknown; blob?: unknown } = {},
  calls: string[] = [],
): typeof fetch {
  return async (url, init) => {
    const path = new URL(String(url));
    assert.equal(path.origin, "https://api.github.com");
    assert.ok(path.pathname.startsWith("/repos/synthetic/service/"));
    assert.equal(init?.method ?? "GET", "GET");
    assert.equal(init?.redirect, "error");
    assert.equal(new Headers(init?.headers).get("Authorization"), "Bearer synthetic-token");
    calls.push(String(url));
    if (path.pathname.endsWith("/pulls/5")) return Response.json(overrides.pr ?? pr);
    if (path.pathname.endsWith("/files")) return Response.json(overrides.files ?? [change]);
    if (path.pathname.endsWith(`/git/blobs/${blobSha}`))
      return Response.json(overrides.blob ?? blob);
    throw new Error("Unexpected GitHub read");
  };
}
const scanner: ScanWorker = async () => native();

test("coordinator verifies native Git blobs, private files, exact diff and scan evidence", async () => {
  let source = "";
  const result = await coordinate(receipt, binding, "synthetic-token", api(), async (path) => {
    source = path;
    assert.deepEqual(await readFile(join(path, "nested/source.py")), content);
    assert.equal((await stat(path)).mode & 0o777, 0o700);
    assert.equal((await stat(join(path, "nested/source.py"))).mode & 0o777, 0o600);
    return native();
  });
  await assert.rejects(access(source));
  assert.deepEqual(result.artifact.files[0]?.changed_lines, [1, 2]);
  assert.equal(result.evidence.git_blob_verification, "sha1-and-byte-count");
  assert.equal(result.artifact.files[0]?.source_sha256, digest(content));
  const finding = review(result.artifact).findings[0]!;
  assert.equal(finding.path, change.filename);
  assert.equal(finding.start_line, 2);
  assert.equal(finding.source_sha256, digest(content));
});

test("queued installation, current head and base repository must match before source reads", async () => {
  const calls: string[] = [];
  await assert.rejects(
    coordinate(
      receipt,
      { ...binding, installation_id: 8 },
      "synthetic-token",
      api({}, calls),
      scanner,
    ),
  );
  assert.equal(calls.length, 0);
  await assert.rejects(
    runJob({}, receipt, { ...binding, repository_id: 43 }, "synthetic-token", api({}, calls)),
  );
  assert.equal(calls.length, 0);
  for (const other of [
    { ...pr, head: { sha: "d".repeat(40) } },
    { ...pr, base: { ...pr.base, repo: { id: 43 } } },
    { ...pr, state: "closed" },
  ]) {
    const reads: string[] = [];
    await assert.rejects(
      coordinate(receipt, binding, "synthetic-token", api({ pr: other }, reads), scanner),
    );
    assert.equal(reads.length, 1);
  }
});

test("native enumeration and blob evidence reject duplication, missing pages and tampering", async () => {
  const cases = [
    { files: [change, change] },
    { pr: { ...pr, changed_files: 2 }, files: [] },
    { files: [{ ...change, filename: "../outside.py" }] },
    { blob: { ...blob, sha: "0".repeat(40) } },
    { blob: { ...blob, size: content.length + 1 } },
    { blob: { ...blob, content: Buffer.from("different").toString("base64") } },
    { blob: { ...blob, content: "%%%=" } },
    { files: [{ ...change, patch: undefined }] },
    { files: [{ ...change, patch: "@@ -0,0 +1,3 @@\n+pass" }] },
  ];
  for (const override of cases) {
    let scanned = false;
    await assert.rejects(
      coordinate(receipt, binding, "synthetic-token", api(override), async () => {
        scanned = true;
        return native();
      }),
    );
    assert.equal(scanned, false);
  }
});

test("scanner errors, skipped files, source substitution and cleanup reject clean results", async () => {
  for (const invalid of [
    { ...native(), scanner_exit: 2 },
    { ...native(), files: { "nested/source.py": "0".repeat(64) } },
    { ...native(), coverage: { expected: ["nested/source.py"], native_scanned: [], errors: [] } },
    {
      ...native(),
      coverage: {
        expected: ["nested/source.py"],
        native_scanned: ["nested/source.py"],
        errors: ["parse"],
      },
    },
  ]) {
    let source = "";
    await assert.rejects(
      coordinate(receipt, binding, "synthetic-token", api(), async (path) => {
        source = path;
        return invalid;
      }),
    );
    await assert.rejects(access(source));
  }
});

test("mixed language PR cannot receive whole-PR success from limited Python rules", async () => {
  const files = [change, { ...change, filename: "other.ts", patch: undefined }];
  const result = await coordinate(
    receipt,
    binding,
    "synthetic-token",
    api({ pr: { ...pr, changed_files: 2 }, files }),
    async () => {
      const report = native();
      report.sarif.runs[0]!.results = [];
      return report;
    },
  );
  const decision = review(result.artifact);
  assert.equal(decision.decision, "neutral");
  assert.equal(decision.check.name, "ReviewShield / Python");
  assert.deepEqual(result.evidence.unassessed, ["other.ts"]);
  assert.match(decision.check.output.summary, /1 changed files unassessed/);
  await assert.rejects(
    coordinate(receipt, binding, "synthetic-token", api({ files: [files[1]] }), scanner),
  );
});

test("diff coordinates require complete non-overlapping native hunks and source bounds", () => {
  assert.deepEqual(
    changedLines(
      {
        ...change,
        status: "modified",
        additions: 1,
        deletions: 1,
        patch: "@@ -1,2 +1,2 @@\n def example(value):\n-    return value\n+    return eval(value)",
      },
      2,
    ),
    [2],
  );
  for (const patch of [
    "@@ -0,0 +3,1 @@\n+pass",
    "@@ -0,0 +1,1 @@\n+pass\n@@ -0,0 +1,1 @@\n+pass",
    "@@ -0,0 +1,2 @@\n+pass",
    "+pass",
  ])
    assert.throws(() => changedLines({ ...change, patch }, 2));
});
