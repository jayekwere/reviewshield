import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { digest, load } from "../src/io.js";
import { requestSchema, review } from "../src/review.js";

const native = (await load(process.argv[2] ?? "")) as {
  files: Record<string, string>;
  sarif: unknown;
  scanner_exit: number;
  coverage: { expected: string[]; native_scanned: string[]; errors: unknown[] };
};
assert.deepEqual(native.coverage.expected, ["safe.py", "unsafe.py"]);
assert.deepEqual(native.coverage.native_scanned, native.coverage.expected);
assert.deepEqual(native.coverage.errors, []);
assert.deepEqual(Object.keys(native.files).sort(), native.coverage.expected);
const files = [];
for (const [path, source_sha256] of Object.entries(native.files)) {
  const bytes = await readFile(`fixtures/${path}`);
  assert.equal(digest(bytes), source_sha256);
  files.push({
    path,
    source_sha256,
    changed_lines: bytes
      .toString("utf8")
      .split("\n")
      .map((_, index) => index + 1),
  });
}
const input = requestSchema.parse({
  schema_version: "1.0",
  tenant: "alder",
  repository: "synthetic/service",
  head_sha: "a".repeat(40),
  base_sha: "b".repeat(40),
  scanner_exit: native.scanner_exit,
  files,
  sarif: native.sarif,
  baseline: [],
});
const result = review(input);
assert.equal(result.decision, "failure");
assert.equal(result.findings.length, 1);
assert.equal(result.findings[0]?.path, "unsafe.py");
assert.equal(result.findings[0]?.start_line, 2);
assert.equal(result.findings[0]?.level, "error");
await writeFile("artifacts/worker-review.json", JSON.stringify(result, null, 2));
console.log("Credential-free native Semgrep coverage and finding fidelity verified");
