# FastGate (MVP) — Standalone "Under-Attack Mode"

Lightweight, stack‑agnostic L7 gate that issues a short‑lived clearance cookie,
challenges the risky tail, and supports HTTP + WebSocket handshakes.

## Quickstart (Docker Compose)

```bash
cd deploy
docker compose up --build
# NGINX: http://localhost:8088/
```

First request should set a `Clearance` cookie and proxy to the mock origin.
Headless clients and hot paths (e.g., `/login`) are challenged.

See `docs/config.md` and `docs/runbook.md` for details.


## Credits

FastGate is primarily authored with the assistance of **Claude**, an AI model from Anthropic, with guidance and direction from the project maintainer.
This attribution reflects the reality that most of the codebase, design scaffolding, and documentation are generated in collaboration with the model.  
