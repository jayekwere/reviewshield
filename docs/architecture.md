# Architecture

ReviewShield separates offline evaluation, signed event intake, credential-free scanning and privileged publication. The default Node web image serves only the local evaluator. It has no App token or publisher route.

```mermaid
flowchart LR
  G[GitHub signed PR event] --> R[Webhook authentication and installation binding]
  R --> Q[Durable receipt queue]
  Q --> C[Trusted checkout coordinator]
  C --> W[Restricted static scanner]
  W --> A[Bound SARIF and source evidence]
  A --> P[Independent publisher process]
  P --> V[Current PR and repository readback]
  V --> K[GitHub check and annotations]
```

| Component | Responsibility |
| --- | --- |
| `src/main.ts` and `src/io.ts` | Offline CLI and stateless local evaluator with bounded HTTP input |
| `src/github.ts` | Original-byte webhook signatures, installation binding, restricted token request and check publication |
| `src/app.ts` | Durable queue and manual publication command; current PR head/base and numeric repository checks |
| `src/review.ts` | Finding fidelity, strongest duplicate severity, exact-source baselines and annotation batches |
| `scanner/worker.py` and `Dockerfile.scanner` | Real Python static scans, clean input copies and exhaustive native file-coverage checks |
| `scanner/scan.py` | Legacy local Semgrep adapter and canonical report-location validation |

The webhook command consumes `BINDINGS_FILE`, `WEBHOOK_SECRET` and `QUEUE_PATH`, defaulting the listener to 127.0.0.1:8081. Queue identity is the signed body hash. The separate publish command loads `APP_KEY_FILE`, requests a token narrowed to one repository, checks the queued artifact against the live PR, and submits structured checks. Privileged requests reject redirects. External publication can be partial or duplicate after an ambiguous network failure; queue completion does not provide distributed exactly-once delivery.

The static scan container has no App credentials. The documented invocation separately enforces no network, a read-only root and input, dropped capabilities, and memory/CPU/PID limits. The worker rejects symlinks, copies only bounded Python files into a clean temporary tree, ignores PR-controlled configuration and requires native coverage of every declared file without scanner errors. Output byte checks occur after process capture; container memory and deadline limits are separate controls. The image alone does not enforce every runtime flag.

A trusted coordinator must acquire the exact checkout and derive its source hashes, changed lines, base/head and scanner artifacts. Checkout scheduling and authenticated artifact handoff remain operator responsibilities. The worker emits scan evidence rather than a complete publication request. The evaluator's tenant field is a sample label, not authentication. There is no Python HTTP identity service here.

The configured Python rule scope is explicit. Off-diff findings still block; annotations target changed lines. Exact-source, severity and expiry requirements prevent a baseline from silently suppressing a changed finding. SARIF suppression flags do not become reviewed exceptions. CodeQL remains a separate CI SARIF producer.

Real App registration, installation, signed event delivery and installation-token check publication remain unverified until exercised. The restricted Semgrep worker and hosted CI are separately verified on synthetic inputs. See [scan worker setup](scan-worker.md) and the [source-backed threat model](threatmodel.md) for exact resources, assumptions and limits.
