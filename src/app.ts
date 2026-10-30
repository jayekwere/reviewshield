import { mkdir, readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { coordinate } from "./coordinator.js";
import { authorizeEvent, bindingSchema, installationToken, publish } from "./github.js";
import { load } from "./io.js";
import { requestSchema } from "./review.js";

const receiptSchema = z
  .object({
    tenant: z.string(),
    repository: z.string(),
    installation_id: z.number().int().positive(),
    repository_id: z.number().int().positive(),
    head_sha: z.string().regex(/^[a-f0-9]{40}$/),
    pr: z.number().int().positive(),
    payload_sha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();
export type Receipt = z.infer<typeof receiptSchema>;
export class Queue {
  private db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(
      "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, receipt TEXT NOT NULL, status TEXT NOT NULL)",
    );
  }
  enqueue(receipt: Receipt): boolean {
    receiptSchema.parse(receipt);
    return (
      this.db
        .prepare("INSERT OR IGNORE INTO jobs VALUES (?,?,'queued')")
        .run(receipt.payload_sha256, JSON.stringify(receipt)).changes === 1
    );
  }
  get(id: string): Receipt {
    const row = this.db.prepare("SELECT receipt FROM jobs WHERE id=?").get(id);
    if (!row) throw new Error("Unknown job");
    return receiptSchema.parse(JSON.parse(String(row.receipt)));
  }
  next(): string | undefined {
    const row = this.db
      .prepare("SELECT id FROM jobs WHERE status='queued' ORDER BY rowid LIMIT 1")
      .get();
    return row ? String(row.id) : undefined;
  }
  claim(id: string): Receipt {
    if (
      this.db.prepare("UPDATE jobs SET status='processing' WHERE id=? AND status='queued'").run(id)
        .changes !== 1
    )
      throw new Error("Job is not queued");
    return this.get(id);
  }
  fail(id: string): void {
    this.db.prepare("UPDATE jobs SET status='failed' WHERE id=? AND status='processing'").run(id);
  }
  complete(id: string): void {
    this.db.prepare("UPDATE jobs SET status='completed' WHERE id=?").run(id);
  }
  close(): void {
    this.db.close();
  }
}

export async function runJob(
  input: unknown,
  receipt: Receipt,
  binding: z.infer<typeof bindingSchema>,
  token: string,
  request: typeof fetch = fetch,
) {
  receiptSchema.parse(receipt);
  bindingSchema.parse(binding);
  if (
    receipt.tenant !== binding.tenant ||
    receipt.repository !== binding.repository ||
    receipt.installation_id !== binding.installation_id ||
    receipt.repository_id !== binding.repository_id
  )
    throw new Error("Queued installation binding changed");
  const artifact = requestSchema.parse(input);
  if (
    artifact.tenant !== receipt.tenant ||
    artifact.repository !== receipt.repository ||
    artifact.head_sha !== receipt.head_sha
  )
    throw new Error("Scan artifact is not bound to queued event");
  const response = await request(
    `https://api.github.com/repos/${binding.repository}/pulls/${receipt.pr}`,
    {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" },
      redirect: "error",
      signal: AbortSignal.timeout(10000),
    },
  );
  if (!response.ok) throw new Error(`GitHub PR HTTP ${response.status}`);
  const pr = z
    .object({
      head: z.object({ sha: z.string() }),
      base: z.object({ sha: z.string(), repo: z.object({ id: z.number() }) }),
      state: z.literal("open"),
    })
    .parse(await response.json());
  if (
    pr.head.sha !== artifact.head_sha ||
    pr.base.sha !== artifact.base_sha ||
    pr.base.repo.id !== binding.repository_id
  )
    throw new Error("Pull request changed since scan");
  return publish(artifact, binding, token, request);
}

async function main(): Promise<void> {
  process.umask(0o077);
  const command = process.argv[2];
  const bindings = z.array(bindingSchema).parse(await load(process.env.BINDINGS_FILE ?? ""));
  const queuePath = process.env.QUEUE_PATH ?? "artifacts/jobs.db";
  await mkdir(dirname(queuePath), { recursive: true, mode: 0o700 });
  const queue = new Queue(queuePath);
  if (command === "work" || command === "worker") {
    let stopping = false;
    const stop = () => {
      stopping = true;
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    try {
      do {
        const key = command === "work" ? (process.argv[3] ?? queue.next()) : queue.next();
        if (!key) {
          if (command === "work") break;
          await new Promise((resolve) => setTimeout(resolve, 1000));
          continue;
        }
        const job = queue.claim(key);
        let publicationAttempted = false;
        try {
          const binding = bindings.find(
            (b) =>
              b.tenant === job.tenant &&
              b.repository === job.repository &&
              b.installation_id === job.installation_id &&
              b.repository_id === job.repository_id,
          );
          if (!binding) throw new Error("Job installation binding removed");
          const token = await installationToken(
            process.env.APP_ID ?? "",
            await readFile(process.env.APP_KEY_FILE ?? "", "utf8"),
            binding.installation_id,
            binding.repository_id,
          );
          const prepared = await coordinate(job, binding, token);
          publicationAttempted = true;
          const result = await runJob(prepared.artifact, job, binding, token);
          queue.complete(key);
          console.log(JSON.stringify({ job: key, ...result, evidence: prepared.evidence }));
        } catch {
          queue.fail(key);
          console.error(
            JSON.stringify({
              job: key,
              status: "failed",
              publication_outcome: publicationAttempted ? "uncertain" : "not_attempted",
            }),
          );
          if (command === "work") process.exitCode = 2;
        }
      } while (command === "worker" && !stopping);
    } finally {
      queue.close();
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
    }
    return;
  }
  if (command === "publish") {
    const job = queue.get(process.argv[3] ?? "");
    const binding = bindings.find(
      (b) =>
        b.tenant === job.tenant &&
        b.repository === job.repository &&
        b.installation_id === job.installation_id &&
        b.repository_id === job.repository_id,
    );
    if (!binding) throw new Error("Job installation binding removed");
    const token = await installationToken(
      process.env.APP_ID ?? "",
      await readFile(process.env.APP_KEY_FILE ?? "", "utf8"),
      binding.installation_id,
      binding.repository_id,
    );
    const result = await runJob(await load(process.argv[4] ?? ""), job, binding, token);
    queue.complete(job.payload_sha256);
    queue.close();
    console.log(JSON.stringify(result));
    return;
  }
  if (command !== "webhook")
    throw new Error(
      "Usage: app webhook | worker | work [JOB_SHA256] | publish JOB_SHA256 TRUSTED_ARTIFACT.json",
    );
  const secret = process.env.WEBHOOK_SECRET ?? "";
  if (secret.length < 32) throw new Error("WEBHOOK_SECRET must contain at least 32 characters");
  createServer(async (req, res) => {
    try {
      if (
        req.method !== "POST" ||
        req.url !== "/webhook" ||
        req.headers["x-github-event"] !== "pull_request"
      ) {
        res.writeHead(404);
        res.end();
        return;
      }
      let length = 0;
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        const b = Buffer.from(chunk);
        length += b.length;
        if (length > 1_048_576) throw new Error("Webhook exceeds limit");
        chunks.push(b);
      }
      const receipt = authorizeEvent(
        Buffer.concat(chunks),
        String(req.headers["x-hub-signature-256"] ?? ""),
        secret,
        bindings,
      );
      const queued = queue.enqueue(receipt);
      res.writeHead(202, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ job: receipt.payload_sha256, queued }));
    } catch {
      res.writeHead(403);
      res.end("Rejected");
    }
  }).listen(Number(process.env.PORT ?? "8081"), process.env.HOST ?? "127.0.0.1");
}
if (process.argv[1]?.endsWith("/app.js") || process.argv[1]?.endsWith("/app.ts"))
  void main().catch((error) => {
    console.error(error instanceof Error ? error.message : "App failed");
    process.exitCode = 2;
  });
