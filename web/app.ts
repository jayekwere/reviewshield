const element = <T extends HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(id);
  return e as T;
};
const input = element<HTMLTextAreaElement>("input");
const decision = element("decision");
const findings = element("findings");
element("subtitle").textContent = "Findings that keep their source, scope, and location.";
element("description").textContent =
  "Inspect new and baseline findings, changed-line targeting, and the exact GitHub check payload. Scanner findings remain evidence, never executable instructions.";
async function reset(): Promise<void> {
  const r = await fetch("/api/sample");
  input.value = JSON.stringify(await r.json(), null, 2);
}
element("reset").addEventListener("click", () => void reset());
element("evaluate").addEventListener("click", async () => {
  findings.replaceChildren();
  decision.textContent = "Evaluating...";
  try {
    const parsed: unknown = JSON.parse(input.value);
    const response = await fetch("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed),
    });
    const result = (await response.json()) as Record<string, unknown>;
    if (!response.ok) throw new Error(String(result.error));
    element("output").textContent = JSON.stringify(result, null, 2);
    decision.textContent = String(result.decision ?? result.status ?? "Analysis complete");
    decision.classList.toggle("bad", result.decision === "deny" || result.decision === "failure");
    const rows = (result.findings ?? result.paths ?? []) as Record<string, unknown>[];
    for (const row of rows) {
      const card = document.createElement("div");
      card.className = "evidence";
      const title = document.createElement("b");
      title.textContent = String(row.message ?? row.summary ?? row.rule ?? row.classification);
      const detail = document.createElement("small");
      detail.textContent = JSON.stringify(row, null, 2);
      card.append(title, detail);
      findings.append(card);
    }
  } catch (error) {
    decision.textContent = error instanceof Error ? error.message : "Evaluation failed";
    decision.classList.add("bad");
  }
});
void reset();
