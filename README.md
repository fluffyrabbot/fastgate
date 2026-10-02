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

Operator data is disabled on the public visitor listener, including for valid
clearance cookies. Enable a separate local listener explicitly:

```bash
./fastgate -config config.yaml -operator-listen 127.0.0.1:9091
```

- **JSON Stats:** `http://127.0.0.1:9091/admin/stats`
- **Prometheus:** `http://127.0.0.1:9091/metrics`

Only literal loopback addresses are accepted; the listener is disabled by default.
Do not publicly reverse-proxy it. The retired public dashboard has been removed;
operator clients can consume these local JSON/Prometheus endpoints.

## Architecture

### Integrated Mode (Simple / Sovereign)
```
Client → FastGate (:8080) → Your App
         ↓
      Stateless JWE Challenge
```

### Sovereign Mesh
FastGate is designed for sovereignty.
- **Stateless Challenges:** Uses JWE (Encrypted JWT) to manage challenge state without a database. Scale to infinity.
- **Cluster Config:** Set `cluster.secret_key` to share state across multiple nodes securely.

### NGINX Mode (Advanced)
```
Client → NGINX (:8088) → Decision Service (:8080) → Origin App
         ↑                      ↓
         └───── clearance ──────┘
```


## Credits

FastGate is primarily authored with the assistance of **Claude**, an AI model from Anthropic, with guidance and direction from the project maintainer.
This attribution reflects the reality that most of the codebase, design scaffolding, and documentation are generated in collaboration with the model.  
