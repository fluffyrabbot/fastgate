# FastGate (MVP) — Standalone "Under-Attack Mode"

Lightweight, stack‑agnostic L7 gate that issues a short‑lived clearance cookie,
challenges the risky tail, and supports HTTP + WebSocket handshakes.

## Quickstart

For local package checks without preparing runtime configuration, use Python 3
and an already running local Podman or Docker, from the repository root:

```bash
python3 tools/tests/package-smoke.py --engine podman
# Or: python3 tools/tests/package-smoke.py --engine docker
```

The fixture generates disposable settings and tests both modes on an internal
container network without publishing ports. See the [runbook](docs/runbook.md#local-container-package-verification)
for prerequisites and limits. It is not a deployment recipe.

The [example configuration](decision-service/config.example.yaml) is a reference
that fails startup validation unchanged: enforcement and secure cookies require
FastGate's own TLS listener and certificate/key paths. Upstream TLS termination
alone does not satisfy this requirement. Preserve these defaults and prepare
operator-supplied certificates, keys, origin and HTTPS settings before startup.

### Option 1: Integrated Proxy Mode (Recommended for simplicity)

**Single binary, zero NGINX dependency**

1. Prepare your runtime configuration from the example above, including TLS and
certificate paths. The following is a **partial routing/configuration illustration**,
not a complete runnable configuration; replace its placeholder key:
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

2. Once the runtime configuration and trusted certificates are ready, run from
   the repository root, substituting your configuration's absolute path:
```bash
cd decision-service
CHALLENGE_PAGE_DIR=../challenge-page go run ./cmd/fastgate -config /absolute/path/to/runtime.yaml
```

Use the HTTPS address matching your certificate and configured listener.

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

The supplied [Compose topology](deploy/docker-compose.yaml) is not a working
secure quickstart unchanged. It loads the unprepared example configuration and
uses HTTP for NGINX's listener and decision-service upstream. A deployment needs
an explicitly configured runtime file, certificate mounts, and compatible HTTPS
listeners/upstreams. Those deployment choices are not supplied by this example.

Use the disposable smoke command above to verify NGINX routing locally. See
[configuration](docs/config.md) and the [runbook](docs/runbook.md) for details.

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
