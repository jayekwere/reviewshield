# Local GitHub App setup

The default web image is an offline evaluator. Live App processing uses a separate signed receiver and trusted Node queue worker on a host with Docker. The scanner container receives selected Python source through standard input and receives no App credentials.

1. Register an App in your own GitHub account. Grant repository checks write, contents read, pull requests read and mandatory metadata read. Subscribe to pull-request events. No organization or account permissions are needed. Install it only on intended repositories.
2. Generate its signing key and store the downloaded file outside the repository with owner-only permissions. This implementation uses the numeric App ID for `APP_ID`. User OAuth and client secrets are not needed.
3. Create a private binding file containing the exact tenant, installation ID, numeric repository ID and full repository name. Those identities must match the signed event and current native repository.

```json
[
  {
    "tenant": "demo",
    "installation_id": 1234,
    "repository_id": 5678,
    "repository": "owner/repository"
  }
]
```

The identifiers above are fictional. Protect the binding, queue directory, key and webhook secret from other host users.

```sh
umask 077
openssl rand -hex 32 > /absolute/private/webhook-secret
chmod 600 /absolute/private/bindings.json /absolute/private/app.private-key.pem
docker build -f Dockerfile.scanner -t reviewshield-scanner .
npm run build
```

Configure the App webhook with a reachable HTTPS URL ending in `/webhook`, JSON payloads and TLS verification. Set its Secret to the text inside the private webhook-secret file. Use the same text for the receiver's `WEBHOOK_SECRET`. Activate the webhook only after the signed receiver is ready. A temporary development tunnel is sufficient for acceptance; persistent hosting is a separate operator deployment.

```sh
export BINDINGS_FILE=/absolute/private/bindings.json
export QUEUE_PATH=/absolute/private/reviewshield.db
export APP_ID=12345
export APP_KEY_FILE=/absolute/private/app.private-key.pem
export SCANNER_IMAGE=reviewshield-scanner
WEBHOOK_SECRET="$(cat /absolute/private/webhook-secret)" node dist/src/app.js webhook
```

Expose only the receiver's loopback port 8081 through the HTTPS endpoint. Keep the offline evaluator on loopback. In a separate terminal with the same private binding, queue and App variables, run:

```sh
node dist/src/app.js worker
```

For supervised acceptance, `node dist/src/app.js work JOB_SHA256` claims one queued event. The worker requests an installation token narrowed to one configured repository, verifies native PR blobs and complete diff evidence, runs the restricted scanner, rechecks the live head/base and publishes the check. Never execute PR hooks, installers or target Python source in the credentialed process.

Check names and conclusions reflect the declared Python rule scope. Other changed files are unassessed and force neutral absent findings; a PR without Python scope cannot produce a clean check. Configure required checks only where this declared scope fits repository policy. CodeQL remains a separate trusted SARIF producer.

Failed or crashed jobs require investigation before deliberate recovery. Native publication can be partial after an ambiguous network failure. Keep worker evidence output privately, and use native check/annotation readback to verify outcomes.

[Native acceptance evidence](github-app-verification.json) records signed deliveries, exact heads, source binding, annotations, replay rejection and stale-head rejection. Delivery identifiers are stored as opaque decimal strings to preserve the provider's 64-bit values. The queue's replay key is the original signed body SHA-256, not that identifier.

After a temporary acceptance session, disable the verification webhook before retiring its tunnel and receiver. Update the URL before a future session. Keep the App restricted to intended repositories and retain its credentials privately.
