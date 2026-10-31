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
  overrides: {
    pr?: unknown;
    files?: unknown;
    blob?: unknown;
    comparison?: unknown;
    commit?: unknown;
    tree?: unknown;
    source_tree?: unknown;
  } = {},
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
    if (path.pathname.includes("/compare/"))
      return Response.json(
        overrides.comparison ??
          comparison(Array.isArray(overrides.files) ? overrides.files : [change]),
      );
    if (path.pathname.endsWith(`/git/commits/${receipt.head_sha}`))
      return Response.json(overrides.commit ?? { sha: receipt.head_sha, tree: { sha: treeSha } });
    if (path.pathname.endsWith(`/git/trees/${treeSha}`))
      return Response.json(overrides.tree ?? headTree());
    if (path.pathname.endsWith(`/git/trees/${sourceTreeSha}`))
      return Response.json(overrides.source_tree ?? sourceTree());
    if (path.pathname.endsWith("/files")) return Response.json(overrides.files ?? [change]);
    if (path.pathname.endsWith(`/git/blobs/${blobSha}`))
      return Response.json(overrides.blob ?? blob);
    throw new Error("Unexpected GitHub read");
  };
}
const scanner: ScanWorker = async () => native();
const treeSha = "e".repeat(40);
const sourceTreeSha = "f".repeat(40);
const comparison = (files: unknown[] = [change]) => ({
  base_commit: { sha: pr.base.sha },
  merge_base_commit: { sha: "d".repeat(40) },
  commits: [{ sha: receipt.head_sha }],
  status: "ahead",
  files,
});
const headTree = () => ({
  sha: treeSha,
  truncated: false,
  tree: [{ path: "nested", sha: sourceTreeSha, type: "tree", mode: "040000" }],
});
const sourceTree = () => ({
  sha: sourceTreeSha,
  truncated: false,
  tree: [{ path: "source.py", sha: blobSha, type: "blob", mode: "100644" }],
});

test("immutable revision selection resists a PR head that changes and returns", async () => {
  const safe = Buffer.from("pass\n");
  const safeSha = createHash("sha1").update(`blob ${safe.length}\0`).update(safe).digest("hex");
  const mutable = { ...change, sha: safeSha, additions: 1, patch: "@@ -0,0 +1,1 @@\n+pass" };
  const original = api({ files: [mutable], comparison: comparison() });
  const transport: typeof fetch = async (url, init) =>
    String(url).endsWith(`/git/blobs/${safeSha}`)
      ? Response.json({
          sha: safeSha,
          encoding: "base64",
          size: safe.length,
          content: safe.toString("base64"),
        })
      : original(url, init);
  const prepared = await coordinate(
    receipt,
    binding,
    "synthetic-token",
    transport,
    async (source) => {
      const bytes = await readFile(join(source, change.filename));
      const report = native();
      report.files[change.filename as "nested/source.py"] = digest(bytes);
      if (bytes.equals(safe)) report.sarif.runs[0]!.results = [];
      return report;
    },
  );
  assert.equal(prepared.artifact.head_sha, receipt.head_sha);
  assert.equal(review(prepared.artifact).decision, "failure");
  assert.equal(prepared.artifact.files[0]?.source_sha256, digest(content));
});

test("immutable comparison and head tree reject ambiguous or substituted source", async () => {
  const invalid = [
    { comparison: comparison([]) },
    { comparison: comparison([change, change]) },
    { comparison: { ...comparison(), base_commit: { sha: "0".repeat(40) } } },
    { comparison: { ...comparison(), commits: [{ sha: "0".repeat(40) }] } },
    { comparison: { ...comparison(), commits: [] } },
    {
      comparison: comparison(
        Array.from({ length: 300 }, (_, i) => ({ ...change, filename: `f${i}.py` })),
      ),
    },
    { tree: { ...headTree(), truncated: true } },
    { tree: { ...headTree(), sha: "0".repeat(40) } },
    { tree: { ...headTree(), tree: [] } },
    { source_tree: { ...sourceTree(), truncated: true } },
    { source_tree: { ...sourceTree(), tree: [{ ...sourceTree().tree[0], sha: "0".repeat(40) }] } },
    { source_tree: { ...sourceTree(), tree: [{ ...sourceTree().tree[0], mode: "120000" }] } },
    { tree: { ...headTree(), tree: [...headTree().tree, ...headTree().tree] } },
    { tree: { ...headTree(), tree: [{ ...headTree().tree[0], sha: "0".repeat(40) }] } },
    { tree: { ...headTree(), tree: [{ ...headTree().tree[0], mode: "120000" }] } },
    { tree: { ...headTree(), tree: [{ ...headTree().tree[0], mode: "160000", type: "commit" }] } },
    { commit: { sha: "0".repeat(40), tree: { sha: treeSha } } },
  ];
  for (const override of invalid) {
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

test("small PR membership reads skip unrelated repository subtrees", async () => {
  const transport = api({
    tree: {
      ...headTree(),
      tree: [
        ...headTree().tree,
        { path: "unrelated", sha: "1".repeat(40), type: "tree", mode: "040000" },
      ],
    },
  });
  const reads: string[] = [];
  await coordinate(
    receipt,
    binding,
    "synthetic-token",
    async (url, init) => {
      reads.push(String(url));
      assert.equal(new URL(String(url)).searchParams.has("recursive"), false);
      return transport(url, init);
    },
    scanner,
  );
  assert.ok(reads.every((url) => !url.includes("1".repeat(40))));
});

test("immutable merge-base evidence preserves live base, rename and removed-file semantics", async () => {
  const renamed = { ...change, status: "renamed", previous_filename: "old.py" };
  const removed = { ...change, filename: "deleted.py", status: "removed", patch: undefined };
  const result = await coordinate(
    receipt,
    binding,
    "synthetic-token",
    api({
      pr: {
        ...pr,
        changed_files: 2,
        head: { ...pr.head, repo: { id: 99, full_name: "fork/service" } },
      },
      comparison: comparison([renamed, removed]),
      files: [renamed, removed],
    }),
    scanner,
  );
  assert.equal(result.artifact.base_sha, pr.base.sha);
  assert.equal(result.evidence.merge_base_sha, "d".repeat(40));
  assert.equal(result.evidence.head_tree_sha, treeSha);
  assert.deepEqual(result.evidence.unassessed, ["deleted.py"]);
});

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
