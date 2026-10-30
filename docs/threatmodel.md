# ReviewShield threat model

## Overview

ReviewShield combines an offline Node SARIF evaluator, a separately started signed webhook receiver and SQLite queue, a credential-free Python static scanner, and a manually invoked privileged GitHub publisher. Default npm and container startup serve the evaluator. They do not receive webhooks, acquire checkouts, schedule scans or publish checks. One independent fresh-context read-only architecture review informed this model; it is not an audit or live App acceptance result.

| Component | Source and role |
| --- | --- |
| Offline CLI/browser evaluator | `src/main.ts:5`, `src/io.ts:21` |
| Findings, source context and baselines | `src/review.ts:112`, `src/review.ts:153` |
| Signed receipts and queue | `src/github.ts:16`, `src/app.ts:20` |
| Queued/live PR binding | `src/app.ts:49` |
| Privileged token and check publication | `src/github.ts:81`, `src/github.ts:123` |
| Restricted worker | `scanner/worker.py:16`, `Dockerfile.scanner:1` |
| Legacy local scanner wrapper | `scanner/scan.py:35` |

| Deployment or workflow | Resource or capability | Configuration and precedence | Safe effective value or location | Readers, writers, or recipients | Enforcing control | Evidence or unknowns |
| --- | --- | --- | --- | --- | --- | --- |
| Host evaluator | Sample, assets and CLI input | CWD fixed sample/assets; check argument | samples/review.json, web assets, or selected request file | Local process/browser | Strict request schema, fixed asset map; CLI paths trusted | `src/main.ts:5`, `src/io.ts:59` |
| Compose evaluator | Listener and files | WORKDIR /app, HOST=0.0.0.0, default port, loopback publication | /app/samples/review.json, /app/web; host 127.0.0.1:8080 | Container peers and loopback clients | UID 10001, read-only root, no capabilities, memory/CPU/tmpfs limits | `Dockerfile:8`, `Dockerfile:19`, `compose.yaml:4`; not an App deployment |
| Manual App receiver | Signed webhook listener | HOST/PORT defaults; WEBHOOK_SECRET environment | 127.0.0.1:8081/webhook by default; secret in receiver memory | GitHub sender and receiver | POST/event routing, original-byte HMAC, bindings and 1 MiB limit | `src/app.ts:115`, `src/app.ts:117`, `src/app.ts:149` |
| Both App commands | Installation/repository bindings | BINDINGS_FILE, no usable fallback | Operator-selected strict JSON file | Receiver and publisher | Binding schema and numeric repository/install checks | `src/app.ts:91`, `src/github.ts:7`; file privacy is operator-owned |
| Both App commands | Durable receipts | QUEUE_PATH or artifacts/jobs.db | Selected SQLite file or cwd/artifacts/jobs.db plus WAL/SHM companions | Receiver writes, publisher reads/completes | umask 077, parent mkdir 0700, body-hash primary key | `src/app.ts:20`, `src/app.ts:88`; existing permissions remain host-owned |
| Manual publisher | App signing key | APP_ID and APP_KEY_FILE | Operator-selected private-key file; key/JWT/token in publisher memory | Publisher; GitHub receives signed JWT | Narrow token request and short JWT lifetime; filesystem privacy | `src/app.ts:101`, `src/github.ts:81` |
| Manual publisher | Trusted artifact and GitHub API writes | Job hash, artifact argument, trusted binding | Selected review JSON; fixed api.github.com token, PR, repository and check-run endpoints | Publisher and GitHub | Queued/live PR and numeric repository binding, restricted token, 10-second requests, redirects rejected | `src/app.ts:49`, `src/github.ts:81`, `src/github.ts:123` |
| Legacy host scanner | Local source/rules/report | scan.py arguments and trusted Semgrep executable | Fixtures, policy/semgrep.yml and operator-selected SARIF output | Semgrep and coordinator | 120-second timeout, no shell, source-location normalization | `scanner/scan.py:35`; does not provide the worker's clean-copy/coverage controls |
| Restricted Docker worker | Source, rules and process | Read-only /input bind; fixed entrypoint and trusted rules | /input, /opt/reviewshield/policy/semgrep.yml, PATH-resolved Semgrep | UID 10001 worker/Semgrep | Caller flags deny network, make root/input read-only, drop capabilities and bound resources | `Dockerfile.scanner:7`, `docs/scan-worker.md:8`; image alone does not enforce all flags |
| Restricted Docker worker | Temporary copies and native reports | HOME=/tmp, TemporaryDirectory, stdout redirection | /tmp/reviewshield-input-random/source and sibling native.sarif; host artifacts/worker-verification.json | Worker, coordinator and authorized output readers | Private temporary lifecycle, source/traversal bounds, native coverage checks; post-run stdout/SARIF acceptance bounds | `scanner/worker.py:20`, `scanner/worker.py:59`, `scanner/worker.py:70`; stderr has no separate byte cap |
| Hosted verification | CI evidence and CodeQL analysis | Workflow-controlled outputs and artifact upload | artifacts/ and CodeQL results, 14-day retention | GitHub artifacts and code-scanning API | Pinned actions, disabled checkout credential persistence, Verify contents:read; separate CodeQL security-events:write | `.github/workflows/verify.yml:7`, `.github/workflows/codeql.yml:13` |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets are the App key, webhook secret, installation token, bindings, receipt state, checkout identity, source hashes, scanner fidelity, baseline authority and GitHub check/annotation integrity. A PR author controls submitted source and scanner-visible content but has no App key, trusted bindings, coordinator authority or publisher invocation by default. A reachable client can send evaluator or webhook requests. Local evaluator tenant labels do not establish authenticated tenancy. Host administrators and trusted maintainers already control their code, configuration, mounts and private files and are outside isolation (`SECURITY.md:6`).

The web evaluator is unauthenticated and stateless. It applies a 1 MiB request bound, Host/Origin checks, fixed assets, CSP and textContent rendering. There is no identity-derived Python web service in this repository (`src/io.ts:10`, `src/io.ts:34`, `web/app.ts:29`). Submitted JSON can demonstrate a synthetic result but cannot by itself authorize a GitHub publication.

Webhook validation authenticates original bytes using HMAC-SHA256 and a minimum-length secret. Supported actions and numeric installation, repository and base-repository identity are checked before queue persistence. The production receiver uses Queue payload-hash uniqueness; the separate ReplayStore export is not its persistence consumer (`src/github.ts:16`, `src/github.ts:23`, `src/app.ts:20`, `src/app.ts:117`).

The restricted worker copies only bounded Python inputs into a clean temporary tree, rejects symlinks and excludes PR-controlled ignore/configuration files. It does not execute target source. Trusted local rules and Semgrep determine the declared Python scope. Nonzero exit, parser/scanner errors, missing native file coverage, skipped declared files and invalid report locations cannot become a clean worker result. Source hashes and expected/scanned file lists accompany SARIF (`scanner/worker.py:16`, `scanner/worker.py:42`, `scanner/worker.py:70`).

Worker stdout/stderr are buffered before acceptance checks; stdout and the SARIF file have post-run 8 MiB acceptance checks, while stderr has no independent byte limit. The supplied Docker memory, time, PID, network, filesystem and capability restrictions are distinct caller-owned controls. Host execution inherits its process environment: component separation does not cleanse credentials from an improperly configured host process. Never mount publisher credentials, host credential directories or the container socket into the worker (`scanner/worker.py:59`, `Dockerfile.scanner:7`, `docs/scan-worker.md:17`).

A trusted coordinator owns checkout acquisition, immutable revision identity, complete source manifests, changed lines, scanner provenance and baseline approval. Worker output alone is not a complete publication request. The verification helper supplies synthetic tenant/repository/head/base values for fixture testing; these do not prove live App acceptance (`scripts/verify-worker.ts:29`). Source hashes supplied directly to the evaluator remain producer assertions.

runJob binds the request tenant, repository and head to its queued receipt, then checks the current open PR head, base SHA and numeric base-repository ID. publish separately verifies the binding and repository identity, but exported publish callers do not automatically receive runJob's queue/live-PR controls (`src/app.ts:49`, `src/github.ts:123`). The App JWT requests an installation token limited to one repository and checks write, contents read and pull requests read. Fixed API destinations, redirect rejection and timeouts constrain credential recipients (`src/github.ts:81`).

Finding deduplication retains strongest severity and distinct occurrences/rules. Baselines require exact tenant/repository/source/fingerprint/severity and unexpired authority; off-diff findings still block while annotations target changed lines in API-sized batches (`src/review.ts:153`). A zero finding result means only the configured scanner scope produced no fresh findings, not that the code is free of vulnerabilities.

Queue completion is not a distributed publication transaction. A repeated/manual job, partial API success or crash can produce duplicate/partial checks. Completed queue status is not an exactly-once claim. Successful publication returns a check ID without independent check-content readback (`src/app.ts:36`, `src/app.ts:94`, `src/github.ts:123`). Private file permissions and existing state directories remain operator responsibilities. Default Compose supplies neither App credentials, persistent App queue mounts, authenticated artifact handoff nor public webhook ingress.

Provided verification context: the restricted Semgrep fixture container and hosted CI were exercised separately. Actual App registration, installation, real signed webhook delivery and privileged check publication remain unverified pending account access confirmation. These distinctions must remain explicit.

## Attack Surface, Mitigations, and Attacker Stories

These scenarios guide review and are not validated findings.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High | Forged webhook targets a different repository installation | Public receiver exposure | Unauthorized queued review | Original-byte HMAC and numeric installation/repository/base binding | Protect secret/binding files; verify real account installation | `src/github.ts:16`, `src/app.ts:117` |
| High | PR content executes with App credentials | Coordinator executes untrusted hooks, builds or imports | Publisher authority disclosure | Separate worker/publisher; credential-free restricted container invocation | Preserve no-credential mounts and operationally authenticate artifact handoff | `scanner/worker.py:16`, `docs/scan-worker.md:17` |
| High | Stale or forged scan artifact produces a clean check | Trusted producer boundary is compromised or bypassed | Misleading privileged approval | Receipt, current PR head/base and repository identity checks | Bind exact checkout bytes and native scanner coverage before invoking runJob | `src/app.ts:49`, `src/github.ts:123` |
| Medium | PR-controlled ignore or parser failure hides a finding | Python source supplied to worker | False clean scan within declared scope | Clean copied tree, no symlinks, exact native file coverage, errors rejected | Preserve adverse scanner/coverage tests and explicit scope | `scanner/worker.py:20`, `scanner/worker.py:70` |
| Medium | Duplicate findings or stale baselines weaken a blocking result | Attacker influences scanner reports or baseline inputs | Incorrect review conclusion | Strongest severity, exact-source baselines, expiry and off-diff blocking | Keep baseline authority separate from PR authors | `src/review.ts:153` |
| Medium | Check text injects active markup or mentions | Malicious source or SARIF strings | Reviewer deception | Neutralized rendering and targeted structured annotations | Preserve data-only rendering and fidelity tests | `src/review.ts:153`, `web/app.ts:29` |
| Low | Publication retry produces duplicate or partial checks | API interruption or repeated manual invocation | Confusing review history | Explicit limitation and queued receipts | Add provider-aware reconciliation before claiming stronger delivery guarantees | `src/app.ts:36`, `src/github.ts:123` |

## Severity Calibration (Critical, High, Medium, Low)

Critical requires a concrete route to broad App/host authority, not merely a forged result in the caller's own offline evaluator. High applies to a reachable authentication, installation binding or privileged artifact-boundary bypass. Medium covers constrained finding suppression, review deception, confidentiality or resource effects with actual prerequisites. Low covers duplicate presentation and local operational defects without new authority. Trusted host/coordinator control is not an attacker privilege gain. Missing live installation evidence limits confidence and must not be converted into either a security guarantee or an asserted vulnerability.

Repository: https://github.com/jayekwere/reviewshield
Version: f5988aa3487733eeae2a6e3ed5e76fbf7d8bac55
