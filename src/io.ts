import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage } from "node:http";
import { resolve } from "node:path";

export const digest = (value: string | Uint8Array): string =>
  createHash("sha256").update(value).digest("hex");
export const load = async (path: string): Promise<unknown> =>
  JSON.parse(await readFile(path, "utf8")) as unknown;
export async function body(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of req) {
    const b = Buffer.from(chunk);
    length += b.length;
    if (length > 1_048_576) throw new Error("Input exceeds 1 MiB");
    chunks.push(b);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
}
export async function serve(
  title: string,
  sample: unknown,
  evaluate: (input: unknown) => Promise<unknown>,
): Promise<void> {
  const port = Number(process.env.PORT ?? "8080");
  const server = createServer(async (req, res) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    if (!/^(127\.0\.0\.1|localhost)(:\d+)?$/.test(req.headers.host ?? "")) {
      res.writeHead(403);
      res.end();
      return;
    }
    try {
      const target = req.url ?? "/";
      if (!target.startsWith("/") || target.startsWith("//") || target.includes("\\"))
        throw new Error("Origin-form request target required");
      const url = new URL(target, "http://localhost");
      if (req.method === "GET" && url.pathname === "/api/sample") {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(sample));
        return;
      }
      if (req.method === "POST" && url.pathname === "/api/evaluate") {
        if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) {
          res.writeHead(403);
          res.end();
          return;
        }
        if (!req.headers["content-type"]?.startsWith("application/json"))
          throw new Error("application/json required");
        const result = await evaluate(await body(req));
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(result));
        return;
      }
      const assets: Record<string, [string, string]> = {
        "/": ["index.html", "text/html"],
        "/app.js": ["app.js", "text/javascript"],
        "/style.css": ["style.css", "text/css"],
      };
      const asset = assets[url.pathname];
      if (req.method !== "GET" || !asset) {
        res.writeHead(404);
        res.end();
        return;
      }
      res.setHeader("Content-Type", asset[1]);
      res.end(await readFile(resolve("web", asset[0])));
    } catch {
      res.writeHead(422, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Input or policy evaluation failed. Inspect the CLI for operator diagnostics.",
        }),
      );
    }
  });
  server.listen(port, process.env.HOST ?? "127.0.0.1", () =>
    console.log(`${title}: http://127.0.0.1:${port}`),
  );
}
