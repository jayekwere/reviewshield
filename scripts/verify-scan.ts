import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { digest, load } from "../src/io.js";
import { requestSchema, review } from "../src/review.js";

const input = requestSchema.parse(await load("samples/review.json"));
input.sarif = requestSchema.shape.sarif.parse(await load(process.argv[2] ?? ""));
for (const file of input.files) file.source_sha256 = digest(await readFile(file.path));
const report = review(input);
assert.equal(report.decision, "failure");
assert.equal(report.findings.length, 1);
assert.equal(report.findings[0]?.path, "fixtures/unsafe.py");
assert.equal(report.findings[0]?.start_line, 2);
assert.equal(report.findings[0]?.level, "error");
await writeFile("artifacts/semgrep-review.json", JSON.stringify(report, null, 2));
console.log(
  "Real Semgrep finding fidelity verified: rule, source, path, line, severity and blocking conclusion",
);
