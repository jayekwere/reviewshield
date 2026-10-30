# ReviewShield threat model

## Overview

Intended use: the runnable repository implementation and its documented local demo. The user requested an open-source implementation with honest security scope. This model describes inspected source, not a security certification or a claim of complete audit coverage.

Data flow: Signed webhook --> installation binding --> durable body-hash queue --> trusted operator scanner artifact --> SARIF review --> live PR/repository readback --> GitHub check.

| Component/source | Responsibility |
| --- | --- |
| `src/app.ts:20` | Durable receipts and manual trusted-worker publication coordination |
| `src/github.ts:16` | Raw-byte HMAC verification |
| `src/app.ts:49` | Receipt and current PR revision binding |
| `src/review.ts:153` | Finding fidelity, source-bound baseline, annotation batches |
| `scanner/scan.py:9` | Pinned local Semgrep invocation without source execution |

| Deployment or workflow | Resource/configuration and effective location | Readers, writers or recipients | Enforcing control or unknown |
| --- | --- | --- | --- |
| Webhook listener | BINDINGS_FILE plus WEBHOOK_SECRET; PORT or 8081; QUEUE_PATH or artifacts/jobs.db | GitHub payload sender and configured installations | HMAC on original bytes, numeric repository/base installation binding, 1 MiB limit, durable body-hash uniqueness |
| Trusted worker | Operator-selected isolated checkout, local rules and SARIF artifact | Trusted operator only; worker scheduler and sandbox are not implemented | Scanner has no App credentials; immutable source/changed-line manifest is an operator obligation |
| Publisher | APP_ID/APP_KEY_FILE; fixed api.github.com; repository-scoped installation token | GitHub receives a signed JWT; only bound repository receives a check | Checks write, contents read, PR read; live PR head/base and numeric repository readback |
| Local workbench | HOST or 127.0.0.1; PORT or 8080 | Local clients, no accounts | Stateless local inspection; no token or publisher route |

## Threat Model, Trust Boundaries, and Assumptions

Protected assets: Webhook secret, App private key, short-lived installation token, repository/tenant binding, immutable source revision, source hashes, baseline decisions and check conclusions.

Webhook authentication binds a signed payload to a configured installation and repository. Queue identity hashes the body, not the unsigned delivery header. A separately trusted worker must derive all scan inputs from that queued immutable revision. Its manifest remains an assertion from that trusted worker. runJob then binds the artifact to the receipt and current PR head/base before publish checks numeric repository identity. SARIF messages and PR body text never become code or instructions. Source-bound baselines include severity and cannot be reused after source or location changes.

Host administrators, private configuration owners and trusted repository maintainers can alter code, files and private state. They are trusted. An ordinary input author does not gain those capabilities by supplying JSON. Public demo credentials represent synthetic roles in one trusted local demonstration. The local stateless TypeScript evaluators do not establish authenticated service tenancy; the Python services derive tenancy from trusted identities. External assertions retain their stated trust prerequisites.

Real App installation and webhook/token/check publication are unverified. Scanner-worker isolation and artifact authentication require operator infrastructure. External publication can leave partial or duplicate checks on ambiguous failure. CodeQL CI is report-only; its artifact needs successful invocation and source-context evidence before review-gate use.

## Attack Surface, Mitigations, and Attacker Stories

These are threat scenarios and review obligations, not reported vulnerabilities. Priority describes plausible impact if the named control fails in its stated deployment. The source table above identifies the actual consumers and controls.

| Priority | Scenario and potential capability gain | Existing source-established controls | Additional mitigation or prerequisite |
| --- | --- | --- | --- |
| High | A sender forges a repository event or replays it under a changed delivery ID. | HMAC, installation/repository/base ID authorization and durable body-hash uniqueness. | Keep the secret private and bind installation configuration out of band. |
| High | A PR author provides a fabricated clean SARIF report or baseline. | Only the trusted worker publication path is authorized; strict schemas, successful scan assertions and stale baseline rejection protect that handoff. | Never expose publisher input to PR authors; isolate scanner credentials and authenticate artifact provenance in production. |
| High | A stale artifact creates a check for a newer PR revision. | Queued head, artifact head, live PR head/base and repository ID must agree. | Treat provider timeouts as uncertain; inspect partial checks before retry. |
| Medium | Contradictory duplicates, path escapes or malicious message text distort findings. | Severity merges conservatively; paths and regions validate; messages render as text; batches retain all findings. | Preserve strongest-level and off-diff gate regression tests. |

## Severity Calibration (Critical, High, Medium, Low)

Critical would require a credible unauthenticated path to broad privileged external execution or equivalent cross-tenant compromise. This model does not establish such a path. A fictional sandbox state change is not critical cloud compromise.

High includes a reachable authorization, approval or gate bypass that grants a materially new capability over another tenant or a deployment decision, with the required privileged consuming workflow present. An input author changing their own local file is a counterexample.

Medium includes bounded local denial of service, decision-fidelity loss or evidence misbinding under realistic deployment prerequisites. Merely changing trusted policy as its administrator is a counterexample.

Low includes limited presentation/integrity confusion without a new privileged operation. A string that is safely rendered as text is controlled behavior, not an injection finding. Confidence depends on source and executable evidence, independently of impact.

One fresh-context independent read-only architecture review informed this model. Source changed during construction; the parent rechecked the controls and source anchors after the reported discrepancies were fixed. Verified negatives are recorded in tests and verification artifacts. External account behavior remains unverified wherever stated.

Repository: https://github.com/jayekwere/reviewshield
Version: 45e97b22c54c76fccdb20a3703c782460f8d843e
