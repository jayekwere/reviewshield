# Architecture

ReviewShield separates offline evaluation, signed event intake, credential-free scanning and privileged publication. The default Node web image serves only the local evaluator. It has no App token or publisher route.

```mermaid
flowchart LR
  G[GitHub signed PR event] --> R[Webhook authentication and installation binding]
  R --> Q[Durable receipt queue]
  Q --> C[Trusted PR blob coordinator]
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
| `src/coordinator.ts` | Native PR enumeration, Git blob verification, diff evidence, private source transfer and isolated scanner execution |
| `scanner/worker.py` and `Dockerfile.scanner` | Real Python static scans, clean input copies and exhaustive native file-coverage checks |
| `scanner/scan.py` | Legacy local Semgrep adapter and canonical report-location validation |

The webhook command consumes `BINDINGS_FILE`, `WEBHOOK_SECRET` and `QUEUE_PATH`, defaulting the listener to 127.0.0.1:8081. Queue identity is the signed body hash. The separate queue worker or advanced publish command loads `APP_KEY_FILE`, requests a token narrowed to one repository, checks the queued artifact against the live PR, and submits structured checks. Privileged requests reject redirects. External publication can be partial or duplicate after an ambiguous network failure; queue completion does not provide distributed exactly-once delivery.

The static scan container has no App credentials. The coordinator invocation enforces no network, a read-only root and bounded source manifest on standard input, dropped capabilities, and memory/CPU/PID limits. The worker rejects symlinks, copies only bounded Python files into a clean temporary tree, ignores PR-controlled configuration and requires native coverage of every declared file without scanner errors. Output byte checks occur after process capture; container memory and deadline limits are separate controls. The image alone does not enforce every runtime flag.

The coordinator reads fixed official GitHub APIs, verifies each native Git blob SHA-1 and byte count, computes SHA-256 source evidence and validates complete diff hunks. It transfers only bounded Python files over standard input, without sharing a host source mount or App credentials with the container. Native expected/scanned paths and hashes must exactly match those verified files. Mixed-language PRs record unassessed files and cannot receive a whole-PR success from Python-only rules. Installation and repository numeric IDs survive in queued receipts and must still match configured bindings at publication. Legacy receipts without those IDs are rejected. Crashed processing jobs require operator investigation and are not automatically retried. Failed publication is recorded as uncertain once publication begins; a failure does not prove no remote check was written. The worker emits scan evidence rather than a complete publication request. The evaluator's tenant field is a sample label, not authentication. There is no Python HTTP identity service here.

The configured Python rule scope is explicit. Off-diff findings still block; annotations target changed lines. Exact-source, severity and expiry requirements prevent a baseline from silently suppressing a changed finding. SARIF suppression flags do not become reviewed exceptions. CodeQL remains a separate CI SARIF producer.

Real App registration, installation, signed event delivery and installation-token check publication remain unverified until exercised. The restricted Semgrep worker and hosted CI are separately verified on synthetic inputs. See [scan worker setup](scan-worker.md) and the [source-backed threat model](threatmodel.md) for exact resources, assumptions and limits.
