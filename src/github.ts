import { createHmac, createSign, timingSafeEqual } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { digest } from "./io.js";
import { type Request, review } from "./review.js";

export const bindingSchema = z
  .object({
    tenant: z.string(),
    installation_id: z.number().int().positive(),
    repository_id: z.number().int().positive(),
    repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
  })
  .strict();
export type Binding = z.infer<typeof bindingSchema>;
export function verifySignature(raw: Buffer, signature: string, secret: string): void {
  if (secret.length < 32 || !/^sha256=[a-f0-9]{64}$/.test(signature))
    throw new Error("Invalid signature");
  const expected = createHmac("sha256", secret).update(raw).digest();
  const supplied = Buffer.from(signature.slice(7), "hex");
  if (!timingSafeEqual(expected, supplied)) throw new Error("Invalid signature");
}
export function authorizeEvent(
  raw: Buffer,
  signature: string,
  secret: string,
  bindings: Binding[],
) {
  if (raw.length > 1_048_576) throw new Error("Webhook too large");
  verifySignature(raw, signature, secret);
  const event = z
    .object({
      action: z.enum(["opened", "reopened", "synchronize"]),
      installation: z.object({ id: z.number().int() }),
      repository: z.object({ id: z.number().int(), full_name: z.string() }),
      pull_request: z.object({
        number: z.number().int().positive(),
        head: z.object({ sha: z.string().regex(/^[a-f0-9]{40}$/) }),
        base: z.object({ repo: z.object({ id: z.number().int() }) }),
      }),
    })
    .parse(JSON.parse(raw.toString("utf8")));
  const binding = bindings.find(
    (b) =>
      b.installation_id === event.installation.id &&
      b.repository_id === event.repository.id &&
      b.repository === event.repository.full_name &&
      b.repository_id === event.pull_request.base.repo.id,
  );
  if (!binding) throw new Error("Unauthorized repository installation");
  return {
    tenant: binding.tenant,
    repository: binding.repository,
    installation_id: binding.installation_id,
    repository_id: binding.repository_id,
    head_sha: event.pull_request.head.sha,
    pr: event.pull_request.number,
    payload_sha256: digest(raw),
  };
}
export class ReplayStore {
  private db: DatabaseSync;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(
      "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS deliveries (hash TEXT PRIMARY KEY)",
    );
  }
  claim(payloadHash: string): boolean {
    return (
      this.db.prepare("INSERT OR IGNORE INTO deliveries VALUES (?)").run(payloadHash).changes === 1
    );
  }
  close(): void {
    this.db.close();
  }
}

const responseJSON = async (response: Response): Promise<unknown> => {
  if (!response.ok) throw new Error(`GitHub HTTP ${response.status}`);
  return response.json();
};
export async function installationToken(
  appId: string,
  privateKey: string,
  installationId: number,
  repositoryId: number,
  request: typeof fetch = fetch,
): Promise<string> {
  if (
    !/^\d+$/.test(appId) ||
    !Number.isSafeInteger(installationId) ||
    installationId <= 0 ||
    !Number.isSafeInteger(repositoryId) ||
    repositoryId <= 0
  )
    throw new Error("Invalid installation context");
  const now = Math.floor(Date.now() / 1000);
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const unsigned = `${b64({ alg: "RS256", typ: "JWT" })}.${b64({ iat: now - 30, exp: now + 540, iss: appId })}`;
  const signature = createSign("RSA-SHA256")
    .update(unsigned)
    .sign(privateKey)
    .toString("base64url");
  const response = await request(
    `https://api.github.com/app/installations/${installationId}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${unsigned}.${signature}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({
        repository_ids: [repositoryId],
        permissions: { checks: "write", contents: "read", pull_requests: "read" },
      }),
      redirect: "error",
      signal: AbortSignal.timeout(10000),
    },
  );
  return z.object({ token: z.string().min(1) }).parse(await responseJSON(response)).token;
}

export async function publish(
  input: Request,
  binding: Binding,
  token: string,
  request: typeof fetch = fetch,
) {
  bindingSchema.parse(binding);
  if (input.tenant !== binding.tenant || input.repository !== binding.repository)
    throw new Error("Publication binding mismatch");
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const base = `https://api.github.com/repos/${binding.repository}`;
  const actual = z
    .object({ id: z.number().int(), full_name: z.string() })
    .parse(
      await responseJSON(
        await request(base, { headers, redirect: "error", signal: AbortSignal.timeout(10000) }),
      ),
    );
  if (actual.id !== binding.repository_id || actual.full_name !== binding.repository)
    throw new Error("Repository identity mismatch");
  const report = review(input);
  const [first, ...remaining] = report.annotation_batches;
  const response = await request(`${base}/check-runs`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      ...report.check,
      output: { ...report.check.output, annotations: first ?? [] },
    }),
    redirect: "error",
    signal: AbortSignal.timeout(10000),
  });
  const check = z.object({ id: z.number().int().positive() }).parse(await responseJSON(response));
  for (const annotations of remaining)
    await responseJSON(
      await request(`${base}/check-runs/${check.id}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify({ output: { ...report.check.output, annotations } }),
        redirect: "error",
        signal: AbortSignal.timeout(10000),
      }),
    );
  return { check_id: check.id, head_sha: input.head_sha };
}
