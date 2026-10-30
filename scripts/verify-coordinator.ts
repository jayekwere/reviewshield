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
for (const name of ["safe.py", "unsafe.py"]) {
  const bytes = await readFile(`fixtures/${name}`);
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
  if (path.endsWith("/files")) return Response.json(files);
  const blob = blobs.get(path.split("/").at(-1) ?? "");
  if (blob) return Response.json(blob);
  throw new Error("Unexpected synthetic GitHub read");
};
const prepared = await coordinate(receipt, binding, "synthetic-token", fakeGitHub, (source) =>
  dockerScan(source, process.argv[2] ?? "reviewshield-scanner"),
);
const result = review(prepared.artifact);
assert.equal(result.decision, "failure");
assert.equal(result.findings.length, 1);
assert.equal(result.findings[0]?.path, "fixtures/unsafe.py");
assert.equal(result.findings[0]?.start_line, 2);
assert.equal(result.findings[0]?.level, "error");
assert.deepEqual(prepared.evidence.assessed, ["fixtures/safe.py", "fixtures/unsafe.py"]);
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
