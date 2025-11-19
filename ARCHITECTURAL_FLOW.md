# FastGate Architectural Flow

This document provides a visual guide to understanding how FastGate's integrated reverse proxy mode works, how components interact, and how requests flow through the system.

## Table of Contents

- [High-Level Architecture](#high-level-architecture)
- [Request Flow](#request-flow)
- [Component Architecture](#component-architecture)
- [Proxy Cache (LRU)](#proxy-cache-lru)
- [Metrics Collection](#metrics-collection)
- [Multi-Origin Routing](#multi-origin-routing)
- [Data Structures](#data-structures)

---

## High-Level Architecture

### NGINX Mode (Traditional Two-Tier)

```
   Client                NGINX              FastGate           Origin
     │                     │                    │                 │
     ├──── Request ───────>│                    │                 │
     │                     │                    │                 │
     │                     ├─ auth_request ────>│                 │
     │                     │                    │                 │
     │                     │<── 200/401/403 ────┤                 │
     │                     │   Set-Cookie       │                 │
     │                     │                    │                 │
     │                     ├─── Proxy ──────────┼────────────────>│
     │                     │                    │                 │
     │<──── Response ──────┤<───────────────────┴─────────────────┤
     │      + Cookie       │                                      │
```

**Characteristics:**
- Two processes to manage (NGINX + FastGate)
- Two config files (`nginx.conf` + `config.yaml`)
- NGINX-specific syntax and configuration
- Two-hop authorization (separate auth_request subrequest)

### Integrated Mode (Single Binary)

```
   Client              FastGate (Single Binary)              Origin
     │                        │                                 │
     ├──── Request ──────────>│                                 │
     │                        │                                 │
     │                   ┌────┴────┐                            │
     │                   │  Authz  │ (inline check)             │
     │                   │ Handler │                            │
     │                   └────┬────┘                            │
     │                        │                                 │
     │                   [Decision]                             │
     │                        │                                 │
     │                   If ALLOW:                              │
     │                        ├────── Proxy ───────────────────>│
     │                        │                                 │
     │<──── Response ─────────┤<────────────────────────────────┤
     │      + Cookie          │                                 │
     │                        │                                 │
     │                   If CHALLENGE:                          │
     │<──── 302 ──────────────┤                                 │
     │   Location: /__uam     │                                 │
```

**Characteristics:**
- Single binary (no dependencies)
- One config file (`config.yaml`)
- Simple YAML syntax
- Inline authorization (no subrequests)

---

## Request Flow

### Detailed Flow Through Integrated Proxy Handler

```
  HTTP Request
      │
      ▼
┌─────────────────────────────────────────────┐
│  proxy.Handler.ServeHTTP()                  │
│  (internal/proxy/handler.go:73)             │
└─────────────────────────────────────────────┘
      │
      │  1. Check if challenge page request?
      ├──────── YES ──────> serveChallengePage()
      │                     (/__uam/index.html, etc.)
      │                     │
      │                     └──> Static file serving
      │
      │  2. NO: Normal request
      ▼
┌─────────────────────────────────────────────┐
│  matchRoute(r)                              │
│  • Host-based: "game.example.com"           │
│  • Path-based: "^/api/"                     │
│  • Default: single origin                   │
└─────────────────────────────────────────────┘
      │
      │  Returns: "http://localhost:3000"
      ▼
┌─────────────────────────────────────────────┐
│  checkAuthorization(r)                      │
│  • Creates authzRecorder                    │
│  • Calls authzHandler.ServeHTTP()           │
│  • Captures status code + cookies           │
└─────────────────────────────────────────────┘
      │
      │  Returns: (decision, statusCode, cookies)
      ▼
┌─────────────────────────────────────────────┐
│  Propagate Set-Cookie headers               │
└─────────────────────────────────────────────┘
      │
      ▼
    Switch on decision:
      │
      ├─ "allow" ────────> proxyToOrigin(w, r, origin)
      │                           │
      │                           ├─> getOrCreateProxy(origin)
      │                           │       │
      │                           │       ├─> Check LRU cache
      │                           │       │   • Hit? MoveToFront + return
      │                           │       │   • Miss? Create new proxy
      │                           │       │   • Evict LRU if at capacity
      │                           │       │
      │                           │       └─> Metrics: cache hit/miss/eviction
      │                           │
      │                           ├─> Set X-Forwarded-* headers
      │                           ├─> Track latency
      │                           └─> proxy.ServeHTTP(w, r)
      │                                   │
      │                                   └─> Metrics: latency, errors
      │
      ├─ "challenge" ────> 302 Redirect to /__uam?return_url=...
      │
      └─ "block" ─────────> 403 Forbidden
```

---

## Component Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              FASTGATE BINARY                               │
│                        (cmd/fastgate/main.go)                              │
└────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
         ┌──────────────┐  ┌─────────────┐  ┌──────────────┐
         │   Config     │  │  Keyring    │  │ Rate Stores  │
         │   Loader     │  │   (JWT)     │  │   (Redis)    │
         └──────────────┘  └─────────────┘  └──────────────┘
                    │
                    │  Creates
                    ▼
         ┌──────────────────────────────────────┐
         │      authz.Handler                   │
         │  • Token validation                  │
         │  • Rate limiting                     │
         │  • Threat intel matching             │
         │  • Challenge logic                   │
         └──────────────────────────────────────┘
                    │
                    │  Injected into
                    ▼
         ┌──────────────────────────────────────┐
         │      proxy.Handler                   │
         │  • Route matching                    │
         │  • Authorization integration         │
         │  • Reverse proxy logic               │
         │  • LRU cache management              │
         │  • Metrics collection                │
         └──────────────────────────────────────┘
                    │
                    │  Wrapped by
                    ▼
         ┌──────────────────────────────────────┐
         │      Middleware Chain                │
         │  Chain(withCommonHeaders)(mux)       │
         │  • Security headers                  │
         │  • (Future: logging, custom logic)   │
         └──────────────────────────────────────┘
                    │
                    │  Served by
                    ▼
         ┌──────────────────────────────────────┐
         │      http.Server                     │
         │  • TLS (optional)                    │
         │  • Graceful shutdown                 │
         │  • Health checks (/healthz)          │
         │  • Metrics endpoint (/metrics)       │
         └──────────────────────────────────────┘
```

### Component Responsibilities

**authz.Handler** (`internal/authz/handler.go`)
- Validates clearance tokens (JWT)
- Enforces rate limits (per-IP, per-token)
- Checks threat intelligence indicators
- Issues challenges when needed
- Returns decision: allow/challenge/block

**proxy.Handler** (`internal/proxy/handler.go`)
- Matches routes (host-based, path-based)
- Calls authz.Handler inline
- Proxies allowed requests to upstream
- Manages proxy cache with LRU eviction
- Serves challenge pages (static files)
- Collects metrics

**Middleware Chain** (`cmd/fastgate/main.go`)
- Composable middleware pattern
- Currently: security headers
- Future: logging, custom headers, A/B testing

---

## Proxy Cache (LRU)

### Data Structure

```
Handler struct:
┌─────────────────────────────────────────────────────────────────────────┐
│  proxies map[string]*cachedProxy                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ "http://localhost:3000" ───> cachedProxy {                       │  │
│  │                                  proxy: *ReverseProxy,            │  │
│  │                                  createdAt: Time,                 │  │
│  │                                  originURL: "...",                │  │
│  │                                  lruElement: *list.Element ───────┼──┼──┐
│  │                              }                                    │  │  │
│  │                                                                   │  │  │
│  │ "http://localhost:4000" ───> cachedProxy { ... } ────────────────┼──┼──┤
│  │                                                                   │  │  │
│  │ "http://localhost:5000" ───> cachedProxy { ... } ────────────────┼──┼──┤
│  └──────────────────────────────────────────────────────────────────┘  │  │
│                                                                         │  │
│  proxiesLRU *list.List (doubly-linked)                                 │  │
│  ┌──────────────────────────────────────────────────────────────────┐ │  │
│  │  Front                                              Back          │ │  │
│  │  (MRU)                                              (LRU)         │ │  │
│  │    │                                                  │           │ │  │
│  │    ▼                    ▼                    ▼        ▼           │ │  │
│  │  ┌────┐  <──>  ┌────┐  <──>  ┌────┐  <──>  ┌────┐               │ │  │
│  │  │ cp │        │ cp │        │ cp │        │ cp │               │ │  │
│  │  └────┘        └────┘        └────┘        └────┘               │ │  │
│  │    ▲             ▲             ▲             ▲                  │ │  │
│  └────┼─────────────┼─────────────┼─────────────┼──────────────────┘ │  │
│       └─────────────┴─────────────┴─────────────┴────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Cache Operations

#### Cache HIT

```
1. Check if origin exists in map
2. Check if TTL expired (5 minutes)
3. If fresh: MoveToFront(lruElement)  ← Keep it hot!
4. Metric: ProxyCacheOps{operation="hit"}++
5. Return cached proxy
```

#### Cache MISS

```
1. Create new ReverseProxy with configured connection pools
2. If cache at capacity (100):
   • back = proxiesLRU.Back()  ← Least recently used
   • CloseIdleConnections()
   • delete(proxies, back.originURL)
   • proxiesLRU.Remove(back)
   • Metric: ProxyCacheOps{operation="eviction"}++
3. Create cachedProxy
4. lruElement = proxiesLRU.PushFront(cp)  ← Add at front
5. proxies[origin] = cp
6. Metric: ProxyCacheOps{operation="miss"}++
```

#### TTL EXPIRATION

```
1. Found in cache but > 5 minutes old (DNS change handling)
2. CloseIdleConnections()
3. proxiesLRU.Remove(lruElement)
4. delete(proxies, origin)
5. Metric: ProxyCacheOps{operation="expiration"}++
6. Create new proxy (treat as miss)
```

### Why LRU?

**Problem:** With random eviction, frequently-used proxies could be evicted while rarely-used ones stay.

**Solution:** LRU ensures the least recently used proxy is evicted first, keeping hot proxies in cache.

**Benefits:**
- Reduces TLS handshakes for popular origins
- Reduces DNS lookups for active upstreams
- Better cache utilization under load

---

## Metrics Collection

### Instrumentation Points

```
Request arrives
    │
    ▼
┌───────────────────────────────┐
│  proxyToOrigin()              │
│                               │
│  start := time.Now()          │◄─── Start latency timer
│  proxy.ServeHTTP(w, r)        │
│  duration := time.Since(start)│
│                               │
│  ProxyLatency                 │◄─── Record latency
│    .WithLabelValues(origin)   │     by origin
│    .Observe(duration.Seconds) │
└───────────────────────────────┘
    │
    │  On proxy error:
    ▼
┌───────────────────────────────┐
│  proxy.ErrorHandler           │
│                               │
│  if timeout:                  │
│    ProxyErrors                │◄─── Count errors
│      .WithLabelValues(        │     by type & origin
│        origin, "timeout")     │
│      .Inc()                   │
│                               │
│  if DNS error:                │
│    ProxyErrors                │
│      .WithLabelValues(        │
│        origin, "dns")         │
│      .Inc()                   │
│                               │
│  if connection refused:       │
│    ProxyErrors                │
│      .WithLabelValues(        │
│        origin, "connection")  │
│      .Inc()                   │
└───────────────────────────────┘
    │
    ▼
┌───────────────────────────────┐
│  getOrCreateProxy()           │
│                               │
│  Cache hit:                   │
│    ProxyCacheOps              │◄─── Track cache
│      .WithLabelValues("hit")  │     effectiveness
│      .Inc()                   │
│                               │
│  Cache miss:                  │
│    ProxyCacheOps              │
│      .WithLabelValues("miss") │
│      .Inc()                   │
│                               │
│  LRU eviction:                │
│    ProxyCacheOps              │
│      .WithLabelValues(        │
│        "eviction")            │
│      .Inc()                   │
│                               │
│  TTL expiration:              │
│    ProxyCacheOps              │
│      .WithLabelValues(        │
│        "expiration")          │
│      .Inc()                   │
└───────────────────────────────┘
```

### Available Metrics

Visit `/metrics` to see Prometheus-formatted metrics:

```
# Proxy latency by origin (histogram)
fastgate_proxy_duration_seconds{origin="http://localhost:3000"}
  count: 1247
  sum: 56.4
  buckets:
    0.01: 234   ← Fast responses
    0.05: 890
    0.1: 1100
    0.5: 1200
    1.0: 1240
    2.5: 1245
    5.0: 1247
    10.0: 1247

# Proxy errors by origin and type (counter)
fastgate_proxy_errors_total{
  origin="http://localhost:3000",
  error_type="timeout"
} 3

fastgate_proxy_errors_total{
  origin="http://localhost:3000",
  error_type="dns"
} 1

# Cache operations (counter)
fastgate_proxy_cache_total{operation="hit"} 1200
fastgate_proxy_cache_total{operation="miss"} 47
fastgate_proxy_cache_total{operation="eviction"} 5
fastgate_proxy_cache_total{operation="expiration"} 12
```

**Use Cases:**
- Track p50/p95/p99 latency per origin
- Identify failing upstreams by error type
- Monitor cache effectiveness (hit rate)
- Alert on high timeout rates

---

## Multi-Origin Routing

### Configuration Example

```yaml
proxy:
  enabled: true
  mode: integrated
  routes:
    - host: "game.example.com"
      origin: "http://localhost:3000"
    - host: "shop.example.com"
      origin: "http://localhost:4000"
    - path: "^/api/"
      origin: "http://localhost:5000"
```

### Routing Logic (First Match Wins)

```
┌──────────────────────────────────────────────────────────────┐
│  Request: GET https://game.example.com/play                  │
│    │                                                          │
│    ├─ Check route[0]: host == "game.example.com"? YES! ────> http://localhost:3000
│    └─ (Don't check further)                                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Request: GET https://shop.example.com/cart                  │
│    │                                                          │
│    ├─ Check route[0]: host == "game.example.com"? NO         │
│    ├─ Check route[1]: host == "shop.example.com"? YES! ────> http://localhost:4000
│    └─ (Don't check further)                                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Request: GET https://example.com/api/users                  │
│    │                                                          │
│    ├─ Check route[0]: host == "game.example.com"? NO         │
│    ├─ Check route[1]: host == "shop.example.com"? NO         │
│    ├─ Check route[2]: path =~ "^/api/"? YES! ───────────────> http://localhost:5000
│    └─ (Don't check further)                                  │
└──────────────────────────────────────────────────────────────┘
```

### Startup Logging

When FastGate starts, it logs the routing configuration:

```
Proxy routing configuration:
  - Mode: multi-origin (3 routes)
    1. host=game.example.com → http://localhost:3000
    2. host=shop.example.com → http://localhost:4000
    3. path=^/api/ → http://localhost:5000
  - Challenge path: /__uam (serving from ./challenge-page)
  - Timeouts: proxy=30000ms, idle=90000ms
```

---

## Data Structures

### Key Go Structs

```go
// Main proxy handler
type Handler struct {
    cfg              *config.Config
    authzHandler     *authz.Handler        // Authorization logic
    proxies          map[string]*cachedProxy  // origin URL → cached proxy
    proxiesLRU       *list.List            // LRU ordering
    proxiesMu        sync.RWMutex          // Protects proxies + proxiesLRU
    challengePageDir string                // Static file serving
}

// Cached proxy with LRU metadata
type cachedProxy struct {
    proxy      *httputil.ReverseProxy  // The actual proxy
    createdAt  time.Time               // For TTL expiration (5 min)
    originURL  string                  // For eviction logging
    lruElement *list.Element           // Position in LRU list
}

// Route matching configuration
type ProxyRoute struct {
    Host    string          // "game.example.com"
    Path    string          // "^/api/"
    Origin  string          // "http://localhost:3000"
    PathRe  *regexp.Regexp  // Compiled path pattern
}

// Proxy configuration
type ProxyCfg struct {
    Enabled              bool
    Mode                 string  // "integrated" | "nginx"
    Origin               string  // Single-origin mode
    Routes               []ProxyRoute
    ChallengePath        string
    TimeoutMs            int
    IdleTimeoutMs        int
    MaxIdleConns         int     // Tunable for heavy traffic
    MaxIdleConnsPerHost  int     // Tunable for heavy traffic
    MaxConnsPerHost      int     // Tunable for heavy traffic
}
```

### Authorization Recorder

```go
// Captures authz response inline (no subrequest needed)
type authzRecorder struct {
    header     http.Header
    statusCode int
    writeOnce  sync.Once  // Thread-safe one-time write
}

// Implements http.ResponseWriter interface
func (r *authzRecorder) Header() http.Header
func (r *authzRecorder) Write(b []byte) (int, error)
func (r *authzRecorder) WriteHeader(statusCode int)
```

The `authzRecorder` allows the proxy handler to capture the authorization decision without making a network call, unlike NGINX's `auth_request` which requires a subrequest.

---

## Deployment Architecture

### Single-Origin (Simple)

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ HTTPS
       ▼
┌─────────────────────────┐
│     FastGate            │
│  • TLS termination      │
│  • Authorization        │
│  • Reverse proxy        │
└──────┬──────────────────┘
       │
       │ HTTP
       ▼
┌─────────────┐
│  Your App   │
│ :3000       │
└─────────────┘
```

**Config:**
```yaml
proxy:
  enabled: true
  origin: "http://localhost:3000"
```

### Multi-Origin (Advanced)

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       │ HTTPS
       ▼
┌─────────────────────────────────────┐
│           FastGate                  │
│  • TLS termination                  │
│  • Authorization                    │
│  • Multi-origin routing             │
└──┬──────────────┬──────────────┬────┘
   │              │              │
   │ game.*.com   │ shop.*.com   │ /api/
   ▼              ▼              ▼
┌──────┐      ┌──────┐      ┌──────┐
│ Game │      │ Shop │      │ API  │
│ :3000│      │ :4000│      │ :5000│
└──────┘      └──────┘      └──────┘
```

**Config:**
```yaml
proxy:
  enabled: true
  routes:
    - host: "game.example.com"
      origin: "http://localhost:3000"
    - host: "shop.example.com"
      origin: "http://localhost:4000"
    - path: "^/api/"
      origin: "http://localhost:5000"
```

### Kubernetes Deployment

```
┌────────────────────────────────────────┐
│         Kubernetes Cluster             │
│                                        │
│  ┌──────────────────────────────────┐ │
│  │        Service (LoadBalancer)    │ │
│  │         :443 (HTTPS)             │ │
│  └────────────┬─────────────────────┘ │
│               │                        │
│  ┌────────────▼─────────────────────┐ │
│  │    FastGate Deployment           │ │
│  │    ┌──────────┐  ┌──────────┐   │ │
│  │    │  Pod 1   │  │  Pod 2   │   │ │
│  │    │ :8088    │  │ :8088    │   │ │
│  │    └──────────┘  └──────────┘   │ │
│  └──────────────────────────────────┘ │
│               │                        │
│  ┌────────────▼─────────────────────┐ │
│  │    Application Deployment        │ │
│  │    ┌──────────┐  ┌──────────┐   │ │
│  │    │  Pod 1   │  │  Pod 2   │   │ │
│  │    │ :3000    │  │ :3000    │   │ │
│  │    └──────────┘  └──────────┘   │ │
│  └──────────────────────────────────┘ │
└────────────────────────────────────────┘
```

**Benefits:**
- Single deployment (no sidecar needed)
- Built-in health checks (`/healthz`, `/readyz`)
- Prometheus metrics (`/metrics`)
- Graceful shutdown on SIGTERM

---

## Performance Characteristics

### Connection Pool Tuning

Default values (moderate traffic):
```yaml
proxy:
  max_idle_conns: 100           # Total across all hosts
  max_idle_conns_per_host: 20   # Per upstream
  max_conns_per_host: 100       # Active connections per upstream
```

Heavy traffic tuning:
```yaml
proxy:
  max_idle_conns: 500
  max_idle_conns_per_host: 100
  max_conns_per_host: 500
```

### Cache Performance

- **Cache size:** 100 proxies max
- **TTL:** 5 minutes (handles DNS changes)
- **Eviction:** LRU (least recently used)
- **Metrics:** Track hit rate via `fastgate_proxy_cache_total`

**Expected hit rate:** >95% for stable multi-origin setups

### Latency

Proxy overhead (authorization + routing):
- p50: < 5ms
- p95: < 25ms
- p99: < 50ms

Track actual latency per origin via `fastgate_proxy_duration_seconds` histogram.

---

## Security Model

### Request Flow Security

```
1. Client Request
   │
   ├─> Check clearance token (JWT)
   │   • Valid? → ALLOW
   │   • Expired/missing? → Continue checks
   │
   ├─> Check rate limits
   │   • IP rate limit exceeded? → BLOCK
   │   • Token rate limit exceeded? → BLOCK
   │
   ├─> Check threat intelligence
   │   • IP in blocklist? → BLOCK
   │   • Hash in IOC list? → BLOCK
   │
   ├─> Under attack mode?
   │   • YES → CHALLENGE (PoW or WebAuthn)
   │   • NO → ALLOW
   │
   └─> Decision: allow/challenge/block
```

### Security Headers (Integrated Mode)

```go
// Automatically added by middleware
"Cache-Control": "no-store"
"X-Content-Type-Options": "nosniff"
"X-Frame-Options": "DENY"
"X-XSS-Protection": "1; mode=block"
"Strict-Transport-Security": "max-age=31536000" (if TLS)
"Content-Security-Policy": "default-src 'none'" (for API endpoints)
```

### Path Traversal Prevention

```go
// Multiple layers of protection
1. URL decoding before validation (catches %2e%2e)
2. Literal ".." check
3. http.ServeFile (Go stdlib protection)
```

### Request Smuggling Prevention

```go
// Detects suspicious header combinations
if Content-Length != "" && Transfer-Encoding != "" {
    log.Printf("WARNING: Both headers present")
    r.Header.Del("Content-Length")  // RFC 7230: TE takes precedence
}
```

---

## Configuration Reference

### Minimal Configuration

```yaml
server:
  listen: ":8088"

proxy:
  enabled: true
  origin: "http://localhost:3000"
```

### Production Configuration

```yaml
server:
  listen: ":8088"
  tls_enabled: true
  tls_cert_file: "/etc/fastgate/cert.pem"
  tls_key_file: "/etc/fastgate/key.pem"

proxy:
  enabled: true
  mode: integrated

  routes:
    - host: "game.example.com"
      origin: "http://game-service:3000"
    - host: "shop.example.com"
      origin: "http://shop-service:4000"

  challenge_path: "/__uam"
  timeout_ms: 30000
  idle_timeout_ms: 90000

  # Heavy-duty tuning
  max_idle_conns: 500
  max_idle_conns_per_host: 100
  max_conns_per_host: 500

modes:
  enforce: true         # Block/challenge (not just observe)
  fail_open: false      # Fail closed on errors
  under_attack: false   # Enable challenge mode

logging:
  level: "info"         # or "debug"
```

---

## Troubleshooting

### High Latency

**Check metrics:**
```
fastgate_proxy_duration_seconds{origin="..."}
```

**Common causes:**
- Upstream slow to respond
- Connection pool exhausted (increase `max_conns_per_host`)
- TLS handshake overhead (check `ResponseHeaderTimeout`)

### High Error Rate

**Check metrics:**
```
fastgate_proxy_errors_total{origin="...", error_type="..."}
```

**Error types:**
- `timeout`: Increase `timeout_ms` or fix upstream
- `dns`: DNS resolution failing (check DNS config)
- `connection`: Upstream not reachable
- `context`: Client disconnected (normal)

### Low Cache Hit Rate

**Check metrics:**
```
fastgate_proxy_cache_total{operation="hit"}
fastgate_proxy_cache_total{operation="miss"}
fastgate_proxy_cache_total{operation="eviction"}
```

**Common causes:**
- Too many unique origins (increase `maxProxyCacheSize` in code)
- Frequent DNS changes (check `expiration` metric)
- LRU eviction under load (normal if cache is small)

### Startup Errors

**Config validation errors:**
```
proxy.origin or proxy.routes required when proxy.enabled
  Example single-origin:
    proxy:
      enabled: true
      mode: integrated
      origin: "http://localhost:3000"
```

**Challenge page directory missing:**
```
challenge page directory does not exist: ./challenge-page
```
Fix: Create the directory or set `CHALLENGE_PAGE_DIR` env var.

---

## Further Reading

- [README.md](README.md) - Getting started guide
- [config.example.yaml](decision-service/config.example.yaml) - Full configuration reference
- [internal/proxy/handler.go](decision-service/internal/proxy/handler.go) - Proxy implementation
- [internal/authz/handler.go](decision-service/internal/authz/handler.go) - Authorization logic
