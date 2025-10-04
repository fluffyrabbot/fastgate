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
- `GET /metrics` exposes Prometheus metrics:
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
