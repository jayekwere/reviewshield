import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { coordinate, dockerScan } from "../src/coordinator.js";
import { review } from "../src/review.js";

const binding = {
  tenant: "alder",
  repository: "synthetic/service",
  repository_id: 42,
  installation_id: 7,
};
const receipt = { ...binding, pr: 5, head_sha: "a".repeat(40), payload_sha256: "c".repeat(64) };
const blobs = new Map<string, unknown>();
const files: {
  filename: string;
  status: string;
  sha: string;
  additions: number;
  deletions: number;
  patch: string;
}[] = [];
for (const name of ["safe.py", "unsafe.py", "suppressed.py"]) {
  const bytes =
    name === "suppressed.py"
      ? Buffer.from(
          "# Analysis-only fixture, never executed.\neval(input('synthetic expression: '))  # nosemgrep: untrusted-eval\n",
        )
      : await readFile(`fixtures/${name}`);
  const sha = createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex");
  const lines = bytes.toString("utf8").trimEnd().split("\n");
  files.push({
    filename: `fixtures/${name}`,
    status: "added",
    sha,
    additions: lines.length,
    deletions: 0,
    patch: `@@ -0,0 +1,${lines.length} @@\n${lines.map((line) => `+${line}`).join("\n")}`,
  });
  blobs.set(sha, {
    sha,
    encoding: "base64",
    size: bytes.length,
    content: bytes.toString("base64"),
  });
}
const fakeGitHub: typeof fetch = async (url) => {
  const path = new URL(String(url)).pathname;
  if (path.endsWith("/pulls/5"))
    return Response.json({
      state: "open",
      changed_files: files.length,
      head: { sha: receipt.head_sha },
      base: { sha: "b".repeat(40), repo: { id: 42 } },
    });
  if (path.includes("/compare/"))
    return Response.json({
      base_commit: { sha: "b".repeat(40) },
      merge_base_commit: { sha: "b".repeat(40) },
      commits: [{ sha: receipt.head_sha }],
      status: "ahead",
      files,
    });
  if (path.endsWith(`/git/commits/${receipt.head_sha}`))
    return Response.json({ sha: receipt.head_sha, tree: { sha: "e".repeat(40) } });
  if (path.endsWith(`/git/trees/${"e".repeat(40)}`))
    return Response.json({
      sha: "e".repeat(40),
      truncated: false,
      tree: [{ path: "fixtures", sha: "f".repeat(40), mode: "040000", type: "tree" }],
    });
  if (path.endsWith(`/git/trees/${"f".repeat(40)}`))
    return Response.json({
      sha: "f".repeat(40),
      truncated: false,
      tree: files.map((file) => ({
        path: file.filename.slice("fixtures/".length),
        sha: file.sha,
        mode: "100644",
        type: "blob",
      })),
    });
  const blob = blobs.get(path.split("/").at(-1) ?? "");
  if (blob) return Response.json(blob);
  throw new Error("Unexpected synthetic GitHub read");
};
const prepared = await coordinate(receipt, binding, "synthetic-token", fakeGitHub, (source) =>
  dockerScan(source, process.argv[2] ?? "reviewshield-scanner"),
);
const result = review(prepared.artifact);
assert.equal(result.decision, "failure");
assert.equal(result.findings.length, 2);
assert.deepEqual(result.findings.map((f) => f.path).sort(), [
  "fixtures/suppressed.py",
  "fixtures/unsafe.py",
]);
assert.ok(result.findings.every((f) => f.start_line === 2 && f.level === "error"));
assert.deepEqual(prepared.evidence.assessed, [
  "fixtures/safe.py",
  "fixtures/suppressed.py",
  "fixtures/unsafe.py",
]);
assert.equal(prepared.evidence.revision_binding, "immutable-compare-and-head-tree");
console.log(
  JSON.stringify({
    verification: "synthetic-native-docker-coordinator",
    github_api: "synthetic-contract",
    scanner: "native-container",
    ...prepared.evidence,
    decision: result.decision,
    findings: result.findings,
  }),
);
