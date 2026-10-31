import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:http";
import { createConnection } from "node:net";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";

async function unusedPort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
  return address.port;
}

function request(
  port: number,
  target: string,
  extra = "",
  method = "GET",
  body = "",
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    let result = "";
    socket.setEncoding("utf8");
    socket.setTimeout(3000, () => socket.destroy(new Error("HTTP test deadline exceeded")));
    socket.on("error", reject);
    socket.on("data", (chunk: string) => {
      result += chunk;
    });
    socket.on("end", () => resolve(result));
    socket.on("connect", () =>
      socket.write(
        `${method} ${target} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n${extra}${body ? `Content-Length: ${Buffer.byteLength(body)}\r\n` : ""}\r\n${body}`,
      ),
    );
  });
}

test("malformed HTTP request targets cannot stop the local evaluator", {
  timeout: 20000,
}, async () => {
  const port = await unusedPort();
  const child = spawn(process.execPath, ["--import", "tsx", "src/main.ts"], {
    env: { ...process.env, HOST: "127.0.0.1", PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk: Buffer) => {
    output = (output + chunk.toString()).slice(-8192);
  });
  child.stderr.resume();
  try {
    for (let i = 0; i < 100 && !output.includes(`127.0.0.1:${port}`); i++) {
      assert.equal(child.exitCode, null, "Evaluator exited during startup");
      await delay(25);
    }
    assert.ok(output.includes(`127.0.0.1:${port}`), "Evaluator did not start");
    assert.match(await request(port, "/api/sample?audit=1"), /^HTTP\/1.1 200/);
    for (const target of ["//a:invalid/", "//[", "/\\evil/", "http://["]) {
      assert.match(await request(port, target), /^HTTP\/1.1 (400|422)/);
      assert.match(await request(port, "/api/sample"), /^HTTP\/1.1 200/);
      assert.equal(child.exitCode, null);
    }
    assert.match(await request(port, "/missing"), /^HTTP\/1.1 404/);
    assert.match(
      await request(
        port,
        "/api/evaluate",
        "Content-Type: application/json\r\nOrigin: https://foreign.invalid\r\n",
        "POST",
        "{}",
      ),
      /^HTTP\/1.1 403/,
    );
    assert.match(
      await request(port, "/api/evaluate", "Content-Type: application/json\r\n", "POST", "{"),
      /^HTTP\/1.1 422/,
    );
    const good = await request(port, "/");
    assert.match(good, /^HTTP\/1.1 200/);
    assert.match(good, /Content-Security-Policy:/i);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGTERM");
      await exited;
    }
  }
});
