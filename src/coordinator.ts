import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import type { Receipt } from "./app.js";
import { type Binding, bindingSchema } from "./github.js";
import { digest } from "./io.js";
import { type Request, requestSchema, safePath } from "./review.js";

const exec = promisify(execFile);
const sha = z.string().regex(/^[a-f0-9]{40}$/);
const changeSchema = z.object({
  filename: safePath,
  sha,
  status: z.enum(["added", "modified", "removed", "renamed", "copied", "changed", "unchanged"]),
  additions: z.number().int().nonnegative(),
  deletions: z.number().int().nonnegative(),
  patch: z.string().max(2_000_000).optional(),
});
type Change = z.infer<typeof changeSchema>;
const nativeWorkerSchema = z
  .object({
    scope: z.literal("configured-python-rules"),
    files: z.record(safePath, z.string().regex(/^[a-f0-9]{64}$/)),
    scanner_exit: z.literal(0),
    coverage: z
      .object({
        expected: z.array(safePath).max(500),
        native_scanned: z.array(safePath).max(500),
        errors: z.array(z.unknown()).length(0),
      })
      .strict(),
    sarif: requestSchema.shape.sarif,
  })
  .strict();
export type ScanWorker = (source: string) => Promise<unknown>;

export function changedLines(change: Change, lineCount: number): number[] {
  if (!change.additions && !change.deletions && !change.patch) return [];
  if (!change.patch) throw new Error("Missing native PR patch; no complete review is possible");
  const result: number[] = [];
  let oldLine = 0,
    newLine = 0,
    oldRemaining = 0,
    newRemaining = 0,
    added = 0,
    deleted = 0,
    started = false;
  const finish = () => {
    if (started && (oldRemaining !== 0 || newRemaining !== 0))
      throw new Error("Truncated PR diff hunk");
  };
  const lines = change.patch.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    const hunk = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$/.exec(line);
    if (hunk) {
      finish();
      const oldStart = Number(hunk[1]),
        newStart = Number(hunk[3]);
      const oldCount = Number(hunk[2] ?? 1),
        newCount = Number(hunk[4] ?? 1);
      if (
        [oldStart, newStart, oldCount, newCount].some(
          (n) => !Number.isSafeInteger(n) || n > 1_000_000,
        ) ||
        (oldCount > 0 && oldStart < 1) ||
        (newCount > 0 && newStart < 1) ||
        (started && (oldStart < oldLine || newStart < newLine))
      )
        throw new Error("Invalid or overlapping PR diff hunks");
      oldLine = Number(hunk[1]);
      newLine = Number(hunk[3]);
      oldRemaining = Number(hunk[2] ?? 1);
      newRemaining = Number(hunk[4] ?? 1);
      started = true;
      continue;
    }
    if (line.startsWith("\\ No newline at end of file")) continue;
    if (line === "" && i === lines.length - 1) continue;
    if (!started) throw new Error("Unexpected PR patch format");
    if (line.startsWith("+")) {
      if (newLine < 1 || newLine > lineCount) throw new Error("Diff line outside source");
      result.push(newLine++);
      newRemaining--;
      added++;
    } else if (line.startsWith("-")) {
      oldLine++;
      oldRemaining--;
      deleted++;
    } else if (line.startsWith(" ")) {
      oldLine++;
      newLine++;
      oldRemaining--;
      newRemaining--;
    } else throw new Error("Unsupported PR diff line");
    if (oldRemaining < 0 || newRemaining < 0 || oldLine < 0 || newLine > lineCount + 1)
      throw new Error("Invalid PR diff range");
  }
  finish();
  if (
    !started ||
    added !== change.additions ||
    deleted !== change.deletions ||
    result.length > 20000 ||
    new Set(result).size !== result.length
  )
    throw new Error("Native PR diff coverage mismatch");
  return result;
}

async function json(response: Response): Promise<unknown> {
  if (!response.ok) throw new Error(`GitHub read HTTP ${response.status}`);
  if (!response.body) throw new Error("Missing GitHub response body");
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > 4_194_304) throw new Error("GitHub response exceeds 4 MiB");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}

export async function dockerScan(
  source: string,
  image = process.env.SCANNER_IMAGE ?? "reviewshield-scanner",
): Promise<unknown> {
  const files: { path: string; content_base64: string; sha256: string }[] = [];
  let total = 0;
  const collect = async (relative: string) => {
    for (const entry of await readdir(join(source, relative), { withFileTypes: true })) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      safePath.parse(path);
      if (entry.isSymbolicLink()) throw new Error("Scanner input contains a symlink");
      if (entry.isDirectory()) await collect(path);
      else {
        if (!entry.isFile() || !path.endsWith(".py"))
          throw new Error("Unexpected scanner source entry");
        const bytes = await readFile(join(source, path));
        total += bytes.length;
        if (bytes.length > 1_000_000 || total > 8_388_608 || files.length >= 500)
          throw new Error("Scanner manifest exceeds source bound");
        files.push({ path, content_base64: bytes.toString("base64"), sha256: digest(bytes) });
      }
    }
  };
  await collect("");
  if (!files.length) throw new Error("Scanner manifest is empty");
  const manifest = JSON.stringify({ schema_version: "1.0", files });
  if (Buffer.byteLength(manifest) > 12_000_000)
    throw new Error("Scanner manifest exceeds byte bound");
  const name = `reviewshield-job-${randomUUID()}`;
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, HOME: process.env.HOME };
  for (const key of [
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
  ])
    if (process.env[key]) env[key] = process.env[key];
  try {
    const pending = exec(
      "docker",
      [
        "run",
        "--rm",
        "--interactive",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "10001:10001",
        "--pids-limit",
        "128",
        "--memory",
        "1g",
        "--cpus",
        "1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=128m",
        image,
        "--stdin",
      ],
      { timeout: 180000, maxBuffer: 16_777_216, env },
    );
    pending.child.stdin?.on("error", () => undefined);
    pending.child.stdin?.end(manifest);
    const { stdout } = await pending;
    return JSON.parse(stdout) as unknown;
  } finally {
    await exec("docker", ["rm", "--force", name], { timeout: 10000, maxBuffer: 65536, env }).catch(
      () => undefined,
    );
  }
}

export async function coordinate(
  receipt: Receipt,
  binding: Binding,
  token: string,
  request: typeof fetch = fetch,
  scan: ScanWorker = dockerScan,
) {
  bindingSchema.parse(binding);
  if (
    receipt.tenant !== binding.tenant ||
    receipt.repository !== binding.repository ||
    receipt.installation_id !== binding.installation_id ||
    receipt.repository_id !== binding.repository_id ||
    !Number.isSafeInteger(receipt.pr) ||
    receipt.pr < 1 ||
    !sha.safeParse(receipt.head_sha).success
  )
    throw new Error("Queued coordination binding mismatch");
  const base = `https://api.github.com/repos/${binding.repository}`;
  const deadline = Date.now() + 300000;
  let reads = 0;
  const get = async (path: string) => {
    if (++reads > 1000 || Date.now() >= deadline)
      throw new Error("Coordination read budget or deadline exceeded");
    return json(
      await request(base + path, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        redirect: "error",
        signal: AbortSignal.timeout(Math.min(10000, deadline - Date.now())),
      }),
    );
  };
  const pr = z
    .object({
      state: z.literal("open"),
      changed_files: z.number().int().min(1).max(299),
      head: z.object({ sha }),
      base: z.object({ sha, repo: z.object({ id: z.number().int() }) }),
    })
    .parse(await get(`/pulls/${receipt.pr}`));
  if (pr.head.sha !== receipt.head_sha || pr.base.repo.id !== binding.repository_id)
    throw new Error("Queued PR identity or head changed");
  const comparison = z
    .object({
      base_commit: z.object({ sha }),
      merge_base_commit: z.object({ sha }),
      commits: z.array(z.object({ sha })).min(1).max(250),
      status: z.enum(["ahead", "diverged"]),
      files: z.array(changeSchema).min(1).max(299),
    })
    .parse(await get(`/compare/${pr.base.sha}...${pr.head.sha}`));
  const changes = comparison.files;
  if (
    comparison.base_commit.sha !== pr.base.sha ||
    comparison.commits.at(-1)?.sha !== pr.head.sha ||
    changes.length !== pr.changed_files ||
    new Set(changes.map((f) => f.filename)).size !== changes.length
  )
    throw new Error("Immutable PR comparison is incomplete or inconsistent");
  const selected = changes.filter((f) => f.filename.endsWith(".py") && f.status !== "removed");
  const unassessed = changes
    .filter((f) => !selected.includes(f))
    .map((f) => f.filename)
    .sort();
  if (!selected.length) throw new Error("No Python scope; no clean check can be produced");
  const commit = z
    .object({ sha, tree: z.object({ sha }) })
    .parse(await get(`/git/commits/${pr.head.sha}`));
  if (commit.sha !== pr.head.sha) throw new Error("Head commit identity mismatch");
  const treeSchema = z.object({
    sha,
    truncated: z.literal(false),
    tree: z
      .array(
        z.object({
          path: z.string().min(1).max(4096),
          sha,
          type: z.enum(["blob", "tree", "commit"]),
          mode: z.string(),
        }),
      )
      .max(100000),
  });
  type Entry = z.infer<typeof treeSchema>["tree"][number];
  const trees = new Map<string, Map<string, Entry>>();
  const readTree = async (id: string) => {
    const cached = trees.get(id);
    if (cached) return cached;
    const tree = treeSchema.parse(await get(`/git/trees/${id}`));
    const entries = new Map(tree.tree.map((entry) => [entry.path, entry]));
    if (
      tree.sha !== id ||
      entries.size !== tree.tree.length ||
      tree.tree.some((entry) => entry.path.includes("/"))
    )
      throw new Error("Head tree identity or completeness mismatch");
    trees.set(id, entries);
    return entries;
  };
  for (const change of selected) {
    let id = commit.tree.sha;
    const parts = change.filename.split("/");
    for (const part of parts.slice(0, -1)) {
      const entry = (await readTree(id)).get(part);
      if (entry?.type !== "tree" || entry.mode !== "040000")
        throw new Error("Selected source parent is not a directory in the pinned head");
      id = entry.sha;
    }
    const entry = (await readTree(id)).get(parts.at(-1) ?? "");
    if (
      !entry ||
      entry.sha !== change.sha ||
      entry.type !== "blob" ||
      !["100644", "100755"].includes(entry.mode)
    )
      throw new Error("Selected source is not a regular file in the pinned head tree");
  }
  const directory = await mkdtemp(join(tmpdir(), "reviewshield-coordinator-"));
  const source = join(directory, "source");
  await mkdir(source, { mode: 0o700 });
  let total = 0;
  const contexts: Request["files"] = [];
  try {
    for (const change of selected) {
      const blob = z
        .object({
          sha,
          encoding: z.literal("base64"),
          size: z.number().int().nonnegative().max(1_000_000),
          content: z.string().max(1_400_000),
        })
        .parse(await get(`/git/blobs/${change.sha}`));
      const encoded = blob.content.replace(/\n/g, "");
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
        throw new Error("Invalid Git blob encoding");
      const bytes = Buffer.from(encoded, "base64");
      total += bytes.length;
      const gitSha = createHash("sha1")
        .update(`blob ${bytes.length}\0`)
        .update(bytes)
        .digest("hex");
      if (
        blob.sha !== change.sha ||
        gitSha !== change.sha ||
        blob.size !== bytes.length ||
        total > 8_388_608
      )
        throw new Error("Git blob identity or byte scope mismatch");
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      const count = text ? text.split("\n").length - (text.endsWith("\n") ? 1 : 0) : 0;
      const lines = changedLines(change, count);
      const path = join(source, change.filename);
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, bytes, { mode: 0o600 });
      contexts.push({ path: change.filename, source_sha256: digest(bytes), changed_lines: lines });
    }
    const native = nativeWorkerSchema.parse(await scan(source));
    const expected = contexts.map((f) => f.path).sort();
    for (const actual of [
      Object.keys(native.files).sort(),
      native.coverage.expected,
      native.coverage.native_scanned,
    ])
      if (JSON.stringify(actual) !== JSON.stringify(expected))
        throw new Error("Worker coverage does not match PR Python blobs");
    for (const file of contexts)
      if (native.files[file.path] !== file.source_sha256)
        throw new Error("Worker source differs from downloaded Git blob");
    const artifact = requestSchema.parse({
      schema_version: "1.0",
      tenant: receipt.tenant,
      repository: binding.repository,
      head_sha: pr.head.sha,
      base_sha: pr.base.sha,
      scanner_exit: 0,
      files: contexts,
      sarif: native.sarif,
      baseline: [],
      scan_scope: { name: "configured-python-rules", assessed: expected, unassessed },
    });
    return {
      artifact,
      evidence: {
        pr: receipt.pr,
        head_sha: pr.head.sha,
        base_sha: pr.base.sha,
        merge_base_sha: comparison.merge_base_commit.sha,
        head_tree_sha: commit.tree.sha,
        revision_binding: "immutable-compare-and-head-tree",
        git_blob_verification: "sha1-and-byte-count",
        worker_report_sha256: digest(JSON.stringify(native)),
        assessed: expected,
        unassessed,
      },
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
