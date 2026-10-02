# FastGate — Runbook

## Local quickstart
```bash
cd deploy
docker compose up --build
```

Visit http://localhost:8088/ — first request should set a `Clearance` cookie.
Try hitting `/login` or set a headless UA to see a challenge:

```bash
curl -i -A "curl/8.0" http://localhost:8088/login
```

You should see a `302` to `/__uam?u=/login`.

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
