# FastGate — Operator Configuration

Copy `decision-service/config.example.yaml` to your own config and set `FASTGATE_CONFIG` accordingly.

## Modes
- `enforce: true` — Gate traffic according to policy.
- `enforce: false` — Observe only (always allow), still issues clearance opportunistically.
- `fail_open: true` — If rate store or decision logic fails, ALLOW.
- `under_attack: true` — Raises risk (+15) and effectively lowers thresholds.

## Cookie
- Name defaults to `Clearance`. Keep payload small, HttpOnly + Secure on.
- `same_site: Lax` works for typical same-site flows. Use `None` for cross-site widgets.
- Prefer eTLD+1 in `domain` if you front multiple subdomains.

## Policy
- `challenge_threshold` vs `block_threshold` tune friction vs safety.
- `paths`: per-path base risk. Protect `/login`, `/api/*`, `/live` more aggressively.
- `ip_rps_threshold` & `token_rps_threshold`: sliding RPS caps over ~10s.

## Challenge
- `difficulty_bits`: proof-of-work cost. 16–20 is a good range; start at 16 in dev.

## WebAuthn (Hardware Attestation)
- `enabled: true|false` — Enable WebAuthn hardware-backed challenges.
- `rp_id: "domain.com"` — Relying party ID (must match your domain).
- `rp_name: "FastGate"` — Display name shown in authenticator UI.
- `rp_origins: ["https://domain.com"]` — List of valid origins for challenges.
- `ttl_sec: 60` — Challenge timeout in seconds.

## Threat Intelligence (STIX/TAXII Federation)
- `enabled: true|false` — Enable federated threat intelligence sharing.
- `cache_capacity: 50000` — Maximum number of indicators to store in memory.
- `peers: [...]` — List of TAXII peer servers to subscribe to.
- `auto_publish: true|false` — Automatically share local attack indicators with peers.

**Note:** Behavioral entropy analysis is automatically applied during PoW challenge completion. The entropy analyzer uses hardcoded thresholds (bot_likelihood >= 0.7 triggers challenge tier adjustment, >= 0.9 triggers block). No configuration is needed.

## Key rotation
- Add a new `kid` to `token.keys`, set `current_kid` to the new key, keep the old one for at least cookie TTL, then remove it.
