# FastGate (MVP) — Standalone "Under-Attack Mode"

Lightweight, stack‑agnostic L7 gate that issues a short‑lived clearance cookie,
challenges the risky tail, and supports HTTP + WebSocket handshakes.

## Quickstart

### Option 1: Integrated Proxy Mode (Recommended for simplicity)

**Single binary, zero NGINX dependency**

1. Create `config.yaml`:
```yaml
version: v1
server:
  listen: ":8080"
  read_timeout_ms: 5000
  write_timeout_ms: 5000

proxy:
  enabled: true
  mode: "integrated"
  origin: "http://localhost:3000"  # Your app

token:
  alg: "HS256"
  keys:
    v1: "your-secret-key-base64"
  current_kid: "v1"

policy:
  challenge_threshold: 60
  block_threshold: 85
```

2. Run FastGate:
```bash
cd decision-service
go run ./cmd/fastgate
# FastGate listening on :8080, proxying to your app
```

That's it! FastGate now sits in front of your application at port 8080.

**Multi-origin routing example** (game + shop):
```yaml
proxy:
  enabled: true
  routes:
    - host: "game.yourdomain.com"
      origin: "http://localhost:3000"
    - host: "shop.yourdomain.com"
      origin: "http://localhost:4000"
```

### Option 2: NGINX Mode (Traditional)

**For advanced deployments requiring NGINX features**

```bash
cd deploy
docker compose up --build
# NGINX: http://localhost:8088/
```

First request sets a `Clearance` cookie and proxies to the origin.
Headless clients and high-risk paths (e.g., `/login`) are challenged.

See `docs/config.md` and `docs/runbook.md` for details.

## Observability

FastGate includes a lightweight, built-in **Admin Dashboard** (Integrated Mode only) for real-time monitoring.

- **Dashboard:** `http://<host>/__uam/dashboard.html`
- **JSON Stats:** `http://<host>/admin/stats`
- **Prometheus:** `http://<host>/metrics`

The dashboard visualizes:
- Real-time allow/block/challenge rates
- Challenge solver success rates (PoW)
- WebAuthn statistics
- System health and proxy errors

## Architecture

### Integrated Mode (Simple)
```
Client → FastGate (:8080) → Your App
         ↓
      Challenge page
         &
      Admin Dashboard
```

### NGINX Mode (Advanced)
```
Client → NGINX (:8088) → Decision Service (:8080) → Origin App
         ↑                      ↓
         └───── clearance ──────┘
```


## Credits

FastGate is primarily authored with the assistance of **Claude**, an AI model from Anthropic, with guidance and direction from the project maintainer.
This attribution reflects the reality that most of the codebase, design scaffolding, and documentation are generated in collaboration with the model.  
