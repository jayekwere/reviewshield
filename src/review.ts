import { z } from "zod";
import { digest } from "./io.js";

const sha = z.string().regex(/^[a-f0-9]{40}$/);
export const safePath = z
  .string()
  .min(1)
  .max(512)
  .refine(
    (p) =>
      !p.startsWith("/") &&
      !p.includes("\\") &&
      !p.split("/").some((s) => s === ".." || s === "." || s === "") &&
      !/[\u0000-\u001f:?#%]/.test(p),
    "Unsafe repository path",
  );
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const region = z
  .object({
    startLine: z.number().int().positive(),
    endLine: z.number().int().positive().optional(),
    startColumn: z.number().int().positive().optional(),
    endColumn: z.number().int().positive().optional(),
  })
  .passthrough();
const result = z
  .object({
    ruleId: z.string().min(1).max(256),
    level: z.enum(["error", "warning", "note", "none"]).optional(),
    message: z.object({ text: z.string().max(10000) }).passthrough(),
    locations: z
      .array(
        z
          .object({
            physicalLocation: z
              .object({
                artifactLocation: z
                  .object({ uri: safePath, uriBaseId: z.literal("%SRCROOT%").optional() })
                  .passthrough(),
                region,
              })
              .passthrough(),
          })
          .passthrough(),
      )
      .min(1)
      .max(100),
    partialFingerprints: z.record(z.string(), z.string()).optional(),
  })
  .passthrough();
const sarif = z
  .object({
    version: z.literal("2.1.0"),
    runs: z
      .array(
        z
          .object({
            tool: z
              .object({
                driver: z
                  .object({
                    name: z.enum(["Semgrep", "Semgrep OSS", "semgrep", "CodeQL"]),
                    version: z.string().optional(),
                    semanticVersion: z.string().optional(),
                    rules: z
                      .array(
                        z
                          .object({
                            id: z.string(),
                            defaultConfiguration: z
                              .object({ level: z.enum(["error", "warning", "note", "none"]) })
                              .optional(),
                          })
                          .passthrough(),
                      )
                      .optional(),
                  })
                  .passthrough(),
              })
              .passthrough(),
            invocations: z
              .array(
                z
                  .object({
                    executionSuccessful: z.literal(true),
                    toolExecutionNotifications: z
                      .array(z.object({ level: z.string().optional() }).passthrough())
                      .optional(),
                  })
                  .passthrough(),
              )
              .min(1),
            results: z.array(result).max(10000),
          })
          .passthrough(),
      )
      .min(1)
      .max(10),
  })
  .passthrough();
const baseline = z
  .object({
    tenant: z.string(),
    repository: z.string(),
    fingerprint: hash,
    level: z.enum(["error", "warning", "note", "none"]),
    source_sha256: hash,
    expires: z.iso.datetime(),
    reason: z.string().min(12).max(500),
  })
  .strict();
export const requestSchema = z
  .object({
    schema_version: z.literal("1.0"),
    tenant: z.string().regex(/^[a-z0-9-]{1,64}$/),
    repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
    head_sha: sha,
    base_sha: sha,
    scanner_exit: z.literal(0),
    files: z
      .array(
        z
          .object({
            path: safePath,
            source_sha256: hash,
            changed_lines: z.array(z.number().int().positive()).max(20000),
          })
          .strict(),
      )
      .max(5000),
    sarif,
    baseline: z.array(baseline).max(10000).default([]),
  })
  .strict();
export type Request = z.infer<typeof requestSchema>;
export type Finding = {
  tool: string;
  rule: string;
  path: string;
  start_line: number;
  end_line: number;
  level: string;
  message: string;
  fingerprint: string;
  source_sha256: string;
  occurrences: number;
  baseline: boolean;
  on_changed_lines: boolean;
};
export const plain = (s: string): string =>
  s.replace(/[<>`]/g, "").replace(/@/g, "[at]").slice(0, 8000);

export function review(value: unknown, now = new Date()) {
  const input = requestSchema.parse(value);
  const files = new Map(input.files.map((f) => [f.path, f]));
  if (files.size !== input.files.length) throw new Error("Duplicate file context");
  const baselineKeys = new Set<string>();
  for (const b of input.baseline) {
    if (
      b.tenant !== input.tenant ||
      b.repository !== input.repository ||
      new Date(b.expires) <= now
    )
      throw new Error("Foreign or expired baseline");
    if (baselineKeys.has(b.fingerprint)) throw new Error("Duplicate baseline");
    baselineKeys.add(b.fingerprint);
  }
  const found = new Map<string, Finding>();
  const used = new Set<string>();
  for (const run of input.sarif.runs) {
    if (run.invocations.some((i) => i.toolExecutionNotifications?.some((n) => n.level === "error")))
      throw new Error("Scanner reported errors");
    for (const r of run.results)
      for (const location of r.locations) {
        const path = location.physicalLocation.artifactLocation.uri;
        const context = files.get(path);
        if (!context) throw new Error("Finding has no trusted source context");
        const start = location.physicalLocation.region.startLine;
        const end = location.physicalLocation.region.endLine ?? start;
        if (end < start || end - start > 10000) throw new Error("Invalid finding region");
        const identity = JSON.stringify([
          input.tenant,
          input.repository,
          run.tool.driver.name.toLowerCase(),
          r.ruleId,
          path,
          start,
          end,
          r.message.text,
        ]);
        const fingerprint = digest(identity);
        const level =
          r.level ??
          run.tool.driver.rules?.find((rule) => rule.id === r.ruleId)?.defaultConfiguration
            ?.level ??
          "warning";
        const old = found.get(fingerprint);
        if (old) {
          old.occurrences++;
          const rank: Record<string, number> = { none: 0, note: 1, warning: 2, error: 3 };
          if ((rank[level] ?? 0) > (rank[old.level] ?? 0)) old.level = level;
          continue;
        }
        found.set(fingerprint, {
          tool: run.tool.driver.name,
          rule: r.ruleId,
          path,
          start_line: start,
          end_line: end,
          level,
          message: plain(r.message.text),
          fingerprint,
          source_sha256: context.source_sha256,
          occurrences: 1,
          baseline: false,
          on_changed_lines: context.changed_lines.some((l) => l >= start && l <= end),
        });
      }
  }
  for (const finding of found.values()) {
    const b = input.baseline.find(
      (b) =>
        b.fingerprint === finding.fingerprint &&
        b.source_sha256 === finding.source_sha256 &&
        b.level === finding.level,
    );
    if (b) {
      finding.baseline = true;
      used.add(b.fingerprint);
    }
  }
  if (input.baseline.some((b) => !used.has(b.fingerprint)))
    throw new Error("Stale or unused baseline entry");
  const findings = [...found.values()].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));
  const fresh = findings.filter((f) => !f.baseline && f.level !== "none");
  const annotations = fresh
    .filter((f) => f.on_changed_lines)
    .map((f) => ({
      path: f.path,
      start_line: f.start_line,
      end_line: f.end_line,
      annotation_level:
        f.level === "error"
          ? ("failure" as const)
          : f.level === "note"
            ? ("notice" as const)
            : ("warning" as const),
      title: plain(`${f.tool}: ${f.rule}`),
      message: f.message,
    }));
  const batches = [];
  for (let i = 0; i < annotations.length; i += 50) batches.push(annotations.slice(i, i + 50));
  return {
    schema_version: "1.0",
    decision: fresh.length ? "failure" : "success",
    head_sha: input.head_sha,
    repository: input.repository,
    tenant: input.tenant,
    findings,
    new_findings: fresh.length,
    unannotated_findings: fresh.filter((f) => !f.on_changed_lines).length,
    check: {
      name: "ReviewShield",
      head_sha: input.head_sha,
      status: "completed" as const,
      conclusion: fresh.length ? ("failure" as const) : ("success" as const),
      output: {
        title: `${fresh.length} new findings`,
        summary: `${findings.length} distinct findings. ${annotations.length} overlap changed lines. Baselines require exact source evidence.`,
      },
    },
    annotation_batches: batches,
  };
}
