import { load, serve } from "./io.js";
import { review } from "./review.js";

async function main(): Promise<void> {
  const command = process.argv[2] ?? "serve";
  if (command === "serve") {
    await serve("ReviewShield", await load("samples/review.json"), async (i) => review(i));
    return;
  }
  if (!["demo", "check"].includes(command))
    throw new Error("Usage: reviewshield check INPUT.json | demo | serve");
  const result = review(
    await load(command === "demo" ? "samples/review.json" : (process.argv[3] ?? "")),
  );
  console.log(JSON.stringify(result, null, 2));
  if (command === "check" && result.decision === "failure") process.exitCode = 1;
}
main().catch((error) => {
  console.error(error instanceof Error ? error.message : "Review failed");
  process.exitCode = 2;
});
