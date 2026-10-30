# Isolated static scan worker

The default web image is an offline SARIF evaluator. `Dockerfile.scanner` is a separate credential-free Semgrep worker. It scans Python files with the repository's trusted local rule pack and never executes target source. It makes no claim to assess other languages or every vulnerability class. CodeQL remains a separate SARIF producer.

```sh
mkdir -p artifacts
docker build -f Dockerfile.scanner -t reviewshield-scanner .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --user 10001:10001 \
  --pids-limit 128 --memory 1g --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --mount "type=bind,source=$PWD/fixtures,target=/input,readonly" \
  reviewshield-scanner > artifacts/worker-verification.json
node --import tsx scripts/verify-worker.ts artifacts/worker-verification.json
```

The runtime flags in this command enforce network and resource restrictions; the image alone does not impose all of them. Mount only the source selected for review. Never mount the App key, webhook secret, identity files, host credential directories or container socket. Keep the privileged publisher outside this worker.

The worker copies bounded Python files into a temporary clean input tree before scanning. PR-controlled ignore files and repository configuration are excluded from that tree, and symlinks are rejected. Limits are 10,000 traversed entries, 500 Python files, 1 MB per Python file, 8 MiB total source, a 120-second scanner deadline, and post-run 8 MiB acceptance checks on captured stdout and the SARIF file. Stdout and stderr are buffered before those checks; stderr has no separate byte cap. The supplied container memory limit bounds the worker process environment as a separate control. An empty declared Python scope is an error. Operator-selected rules and the worker image are trusted configuration.

Native Semgrep JSON must report every declared Python file as scanned and contain no parser or scanner errors. Exit failure, skipped files, missing coverage and malformed report locations cannot become a clean report. The worker emits native SARIF, source SHA-256 values and explicit expected/scanned coverage. A trusted coordinator must bind those exact bytes and changed lines to the queued PR's current head/base before publication. `runJob` independently rechecks the live PR revision and numeric base-repository ID.

For a live App, start the signed webhook receiver using a private binding file, scan the queued revision in this worker, construct the strict review request, and invoke the separate publisher. Scheduling and fetching a checkout remain trusted coordinator operations. A local checkout name is not proof of a PR revision. Do not execute PR build scripts, dependency installers, hooks or imported Python code in the publisher process. There is no general automatic checkout runner or hosted production App deployment in this repository.

The verification workflow executes this exact restricted container against synthetic source and asserts the real Semgrep rule, source digest, path, line, severity, file coverage and blocking review decision. Its synthetic head/base values do not represent a live App test. Live App account acceptance is recorded separately when exercised. Package version and scanner-reported version are preserved independently as described in the main verification documentation.
