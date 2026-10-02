# FastGate — Runbook

## Local quickstart

From the repository root, with Python 3 and an already running local Podman or
Docker, run the disposable package checks without preparing runtime configuration:

```bash
python3 tools/tests/package-smoke.py --engine podman
# Or: python3 tools/tests/package-smoke.py --engine docker
```

See [local container package verification](#local-container-package-verification)
for prerequisites, scope and cleanup. The fixture generates synthetic HTTP
settings inside an isolated network; it does not configure a deployment.

### Runtime configuration prerequisite

The [example configuration](../decision-service/config.example.yaml) is not
runnable unchanged. It enables enforcement and secure cookies but omits TLS.
Startup validation requires `server.tls_enabled: true` with `tls_cert_file` and
`tls_key_file`; serving TLS additionally requires the referenced certificate/key
files. Upstream TLS termination alone does not satisfy this validation rule.
Keep enforcement and secure cookies enabled, and provide operator-supplied trusted
certificates and matching HTTPS settings in your own runtime configuration.

The supplied [Compose file](../deploy/docker-compose.yaml) loads that example
without a runtime override or certificate mounts. Its NGINX listener and upstream
to the decision service use HTTP. Therefore `docker compose up --build` does not
provide a working HTTP clearance flow unchanged. Configuring
runtime mounts and compatible HTTPS listeners/upstreams is a deployment step;
this runbook does not select certificate provisioning or mount policy.

## Under Attack
Set `under_attack: true` to bias scoring up (more challenges) without changing path rules.

## Observe vs Enforce
- **Observe** (enforce=false) — Always ALLOW (204) but the decision service will still mint cookies. Use this to monitor FP before enforcing.
- **Enforce** — Apply thresholds strictly; unauthenticated WS upgrades are denied (401 / challenge).

## Health & metrics
- `GET /healthz` and `/readyz` on the decision service return 200.
- Start with `-operator-listen 127.0.0.1:9091` to enable local operator access. It is disabled by default and accepts only literal loopback bind addresses; never publicly reverse-proxy it.
- `GET /admin/stats` on that separate listener returns a JSON metrics summary in either mode. Public visitor requests to this endpoint and `/metrics` return 404, regardless of clearance.
- `GET /metrics` on the operator listener exposes Prometheus metrics:
  - `fastgate_authz_decision_total{action}`
  - `fastgate_clearance_issued_total`
  - `fastgate_challenge_*_total`
  - `fastgate_ws_upgrades_total{result}`

## Failure modes
- If decision service is unavailable and `fail_open: true`, NGINX will get 5xx at auth subrequest; **treat as ALLOW** by toggling to Observe or temporarily disabling auth_request (manual step).
- Challenge API down? The page will render but completion fails; advise temporarily setting `enforce=false` to avoid gating.

## WebSockets (LiveView)
- FastGate checks clearance during HTTP Upgrade to `/live`. If missing/invalid, a 302 to `/__uam` is returned. Once upgraded, the connection is not re-challenged.
- For a full WS handshake (101), your origin must support WebSockets. The bundled mock origin is HTTP-only.

## Local container package verification

The decision image supports both existing modes. Its builder uses the module's
Go 1.24.7 toolchain. Integrated mode serves the bundled challenge page and scripts
from `/app/challenge-page`, selected by `CHALLENGE_PAGE_DIR`; a custom asset mount
can override that variable. NGINX mode continues to serve assets from the separate
NGINX image. NGINX redirects `/__uam` to `/__uam/` (preserving the return
query) so the HTML's relative JavaScript URLs resolve inside its asset mount. Set `proxy.enabled: true` and `proxy.mode: integrated` in an explicit
runtime configuration to select integrated mode; the bundled example still
selects the separate decision service.

The example configuration is a reference, not a production-ready runtime file.
Supply deployment-specific keys, origin and TLS/cookie settings at runtime. The
root `.dockerignore` allowlists build inputs and excludes `.env`, private configs,
backups, Git metadata and runtime files from image contexts. The decision builder
copies only module files and Go source directories, not the repository root.

With an already running local Podman (or Docker) and Python 3:

```bash
python3 tools/tests/package-smoke.py --engine podman
# Alternatively: python3 tools/tests/package-smoke.py --engine docker
```

This test exports allowlisted tracked files at their current working-tree versions
into a temporary context, builds local images, creates an internal container
network, and generates disposable keys/configuration outside the image. It checks
served assets, a synthetic PoW-to-clearance-to-origin request, proxy trust,
operator isolation, startup errors, shutdown, and the NGINX routing contract.
It publishes no ports or images and removes its named containers, network and
images on exit. Base images/build caches may remain. First use needs network
access to retrieve public base images and Go modules; application requests stay
inside the disposable network. This is local package proof, not deployment or
production validation. No local runtime configuration is loaded by the fixture.

The optional `--image LOCAL_IMAGE --expect-missing-assets` mode reproduces the
pre-fix integrated startup failure, after correcting only the old builder version
in a disposable copy of the original Dockerfile.

Operator access remains an explicit loopback-only listener inside the container
(e.g. `-operator-listen 127.0.0.1:9091`); publishing a container port does not make
that listener a public API. The packaging does not add trusted proxy ranges or
change operator authorization.

### Verified locally on 2026-10-02

- The original Dockerfile failed at `go mod download`: the Go 1.22 builder could
  not satisfy the module's Go 1.24 requirement. With only the builder corrected in
  a disposable copy, integrated startup failed because `challenge-page` was absent.
- The corrected decision image built and passed the synthetic integrated checks
  above on the existing local Podman Linux/ARM64 runtime. Explicit missing-directory
  startup rejection and non-loopback operator-listener rejection remained intact.
- The NGINX browser-relative script test reproduced an existing `/app.js` origin
  routing defect. The slash redirect and asset mount fixed it without changing
  authorization thresholds, trusted proxies or runtime listener configuration.
- Full `go test ./...`, `go test -race ./...`, `go vet ./...` and a native binary
  build passed with local Go 1.27.1; the container build used Go 1.24.7.

Limitations: these are synthetic local checks, not production deployment, TLS,
browser/authenticator, or load-test evidence. The example configuration still
needs operator-provided runtime values: in particular its secure-cookie setting
with enforcement and no TLS fails configuration validation unchanged. The fixture
uses explicit disposable HTTP settings instead. No live configuration was loaded
or changed, no image was published, and no host ports were exposed. GitHub had no
Actions workflows configured at verification time; absent remote checks are not
reported as a passing CI run.

### Admission and redirect boundary regressions (2026-10-02)

The integrated authorization path now derives client identity using configured
trusted proxy CIDRs, matching the challenge endpoints. It overwrites incoming
`X-Client-IP` even when the socket address is invalid; untrusted `X-Forwarded-For`
and `X-Real-IP` cannot select a new admission bucket. Trusted chains still stop at
the first untrusted hop and distinct legitimate clients retain separate buckets.

The shared return-path sanitizer rejects literal or decoded backslashes and
preserves escaped path bytes. This prevents browser interpretation of a returned
backslash as an external authority and avoids decoding safe `%23`, `%3F` or `%25`
path bytes into redirect syntax. Ordinary same-origin paths and queries remain
supported. WebAuthn's atomic consumption and replay behavior are unchanged.

Both original findings were reproduced in disposable tracked-source fixtures.
Regression tests cover actual authz admission, multi-line/forged/malformed proxy
chains, IPv6, software-only WebAuthn completion and replay, and escaped redirects.
The package smoke fixture holds a synthetic WebSocket open while retrying forged
identities and captures PoW completion `Location` headers without following them.
Full Go tests, race tests, vet, build and both packaged modes passed. An offline
WHATWG URL parser check confirmed the original cross-origin interpretation and
same-origin resolution of the corrected outputs; no external target was contacted.

These checks do not constitute production deployment, real-authenticator or live
browser navigation evidence. Existing TLS/example-configuration and absent-CI
limitations above still apply; no live settings or cookie defaults were changed.
