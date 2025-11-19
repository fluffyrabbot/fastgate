# FastGate Circuit Breaker

FastGate includes a production-ready circuit breaker implementation to protect against cascading failures when proxying to backend services.

## Overview

The circuit breaker pattern prevents FastGate from repeatedly calling a failing backend service, allowing the backend time to recover while failing fast for incoming requests.

### Benefits

- **Prevents Cascading Failures**: Stops overwhelming an already failing backend
- **Faster Failure Detection**: Fails fast when backend is unhealthy (503 in <1ms vs 30s timeout)
- **Automatic Recovery**: Automatically attempts recovery after a timeout period
- **Per-Backend Isolation**: Each backend origin has its own circuit breaker
- **Observable**: Full Prometheus metrics for monitoring

## How It Works

### States

The circuit breaker operates in three states:

```
┌──────────┐
│  CLOSED  │◄──────────────────────────────┐
│ (Normal) │                                │
└────┬─────┘                                │
     │                                      │
     │ failures >= threshold                │
     │                                      │
     ▼                                      │
┌──────────┐                                │
│   OPEN   │                         2+ successes
│(Failing) │                                │
└────┬─────┘                                │
     │                                      │
     │ timeout elapsed                      │
     │                                      │
     ▼                                      │
┌────────────┐                              │
│ HALF-OPEN  │──────────────────────────────┘
│ (Testing)  │
└────────────┘
     │
     │ 1 failure
     │
     └──────────────► OPEN
```

#### 1. Closed (Normal Operation)
- All requests flow through to backend
- Failures are tracked
- If `failure_threshold` consecutive failures occur, transitions to **Open**

#### 2. Open (Circuit Tripped)
- **All requests are rejected with 503** (no backend calls)
- Fails fast in <1ms (vs 30s timeout)
- After `timeout_sec` elapses, transitions to **Half-Open**

#### 3. Half-Open (Testing Recovery)
- Limited requests are allowed through to test backend
- If `success_threshold` consecutive successes occur → transitions to **Closed**
- If **any** failure occurs → immediately transitions back to **Open**

## Configuration

Add to your `config.yaml`:

```yaml
proxy:
  enabled: true
  origin: "http://backend:8080"

  circuit_breaker:
    enabled: true                # Enable circuit breaker
    failure_threshold: 5         # Open after N consecutive failures
    success_threshold: 2          # Close after N consecutive successes (in half-open)
    timeout_sec: 30               # Wait N seconds before attempting recovery
    minimum_request_threshold: 3  # Need at least N requests to trip circuit
    sliding_window_sec: 10        # Track failures over N second window
```

### Configuration Tuning

#### Aggressive (Fail Fast)
Fast failure detection, suitable for critical backends with strict SLAs:

```yaml
circuit_breaker:
  enabled: true
  failure_threshold: 3      # Open quickly
  success_threshold: 3      # Require more successes before trusting
  timeout_sec: 15           # Short recovery window
  minimum_request_threshold: 2
  sliding_window_sec: 5
```

**Use when:**
- Backend failures are catastrophic
- You want to fail fast
- Backend recovery is usually quick

#### Conservative (Tolerant)
Tolerates transient errors, suitable for backends with occasional hiccups:

```yaml
circuit_breaker:
  enabled: true
  failure_threshold: 10     # Tolerate more failures
  success_threshold: 2      # Quick recovery
  timeout_sec: 60           # Longer recovery window
  minimum_request_threshold: 5
  sliding_window_sec: 15
```

**Use when:**
- Backend has occasional transient errors
- You want to avoid unnecessary trips
- Backend recovery takes time

#### Balanced (Production Default)
Good starting point for most deployments:

```yaml
circuit_breaker:
  enabled: true
  failure_threshold: 5
  success_threshold: 2
  timeout_sec: 30
  minimum_request_threshold: 3
  sliding_window_sec: 10
```

## What Counts as a Failure?

Circuit breaker tracks **backend failures**, not client errors:

| Status Code Range | Circuit Breaker | Reason |
|-------------------|----------------|---------|
| **2xx** (Success) | ✅ Success | Backend is healthy |
| **3xx** (Redirect) | ✅ Success | Backend responded correctly |
| **4xx** (Client Error) | ⏸️ **Ignored** | Client's fault, not backend's |
| **5xx** (Server Error) | ❌ **Failure** | Backend is unhealthy |
| **Timeout** | ❌ **Failure** | Backend not responding |
| **Connection Refused** | ❌ **Failure** | Backend unreachable |
| **DNS Error** | ❌ **Failure** | Backend cannot be resolved |

**Key Insight**: 4xx errors (bad requests, unauthorized, not found) are **ignored** by the circuit breaker because they indicate client problems, not backend health issues.

## Monitoring

### Prometheus Metrics

FastGate exposes three circuit breaker metrics:

#### 1. `fastgate_proxy_circuit_state`
**Type**: Gauge
**Labels**: `origin`
**Values**:
- `0` = Closed (normal)
- `1` = Open (failing)
- `2` = Half-Open (testing)

```promql
# Check circuit breaker state
fastgate_proxy_circuit_state{origin="http://backend:8080"}

# Alert when circuit opens
fastgate_proxy_circuit_state{origin=~".*"} == 1
```

#### 2. `fastgate_proxy_circuit_open_total`
**Type**: Counter
**Labels**: `origin`

Counts requests **rejected** due to open circuit.

```promql
# Rate of rejected requests
rate(fastgate_proxy_circuit_open_total[5m])

# Alert on high rejection rate
rate(fastgate_proxy_circuit_open_total[5m]) > 10
```

#### 3. `fastgate_proxy_circuit_transitions_total`
**Type**: Counter
**Labels**: `origin`, `from_state`, `to_state`

Tracks state transitions for debugging.

```promql
# Recent state transitions
increase(fastgate_proxy_circuit_transitions_total[10m])

# Alert on frequent trips
rate(fastgate_proxy_circuit_transitions_total{to_state="open"}[5m]) > 0.1
```

### Grafana Queries

#### Circuit Breaker Status Panel
```promql
fastgate_proxy_circuit_state{origin=~"$origin"}
```
Value mappings:
- `0` → "✅ Closed"
- `1` → "🔴 Open"
- `2` → "⚠️ Half-Open"

#### Rejection Rate Panel
```promql
sum(rate(fastgate_proxy_circuit_open_total{origin=~"$origin"}[5m])) by (origin)
```

#### State Transition Timeline
```promql
increase(fastgate_proxy_circuit_transitions_total{origin=~"$origin"}[1h])
```

### Alerting Rules

Recommended Prometheus alerts:

```yaml
groups:
  - name: circuit_breaker
    rules:
      # Alert when circuit opens
      - alert: FastGateCircuitBreakerOpen
        expr: fastgate_proxy_circuit_state == 1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Circuit breaker open for {{ $labels.origin }}"
          description: "Backend {{ $labels.origin }} is failing, circuit breaker opened"

      # Alert on high rejection rate
      - alert: FastGateCircuitBreakerHighRejections
        expr: rate(fastgate_proxy_circuit_open_total[5m]) > 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High circuit breaker rejection rate"
          description: "{{ $value }} requests/s rejected due to open circuit"

      # Alert on frequent trips
      - alert: FastGateCircuitBreakerFlapping
        expr: rate(fastgate_proxy_circuit_transitions_total{to_state="open"}[10m]) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Circuit breaker flapping for {{ $labels.origin }}"
          description: "Circuit breaker transitioning to open frequently, check backend"
```

## Logs

Circuit breaker state changes are logged at `INFO` level:

```json
{
  "level": "info",
  "backend": "http://backend:8080",
  "old_state": "closed",
  "new_state": "open",
  "time": "2025-11-19T10:30:45Z",
  "message": "circuit breaker state transition"
}
```

When circuit opens:
```json
{
  "level": "error",
  "backend": "http://backend:8080",
  "failures": 5,
  "requests": 10,
  "time": "2025-11-19T10:30:45Z",
  "message": "circuit breaker opened"
}
```

When circuit recovers:
```json
{
  "level": "info",
  "backend": "http://backend:8080",
  "successes": 2,
  "time": "2025-11-19T10:31:20Z",
  "message": "circuit breaker recovered"
}
```

## Testing

### Manually Test Circuit Breaker

1. **Start FastGate** with circuit breaker enabled
2. **Stop your backend** service
3. **Send requests** to FastGate:
   ```bash
   # First few requests will timeout (30s each)
   curl -v http://localhost:8080/

   # After 5 failures, circuit opens
   # Next requests fail fast (503 in <1ms)
   curl -v http://localhost:8080/
   # < HTTP/1.1 503 Service Unavailable
   # < Content-Type: text/plain
   # service temporarily unavailable
   ```

4. **Restart backend** service
5. **Wait 30 seconds** (timeout period)
6. **Send requests** - circuit will test recovery:
   ```bash
   # First 2 requests test backend (half-open)
   curl http://localhost:8080/
   curl http://localhost:8080/

   # After 2 successes, circuit closes
   # Normal operation resumes
   ```

### Load Testing with Circuit Breaker

Use k6 to simulate backend failure:

```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 100 }, // Ramp up
    { duration: '3m', target: 100 }, // Sustain
  ],
};

export default function () {
  let res = http.get('http://localhost:8080/');

  check(res, {
    'status is 200 or 503': (r) => r.status === 200 || r.status === 503,
  });

  // Log circuit breaker rejections
  if (res.status === 503 && res.body.includes('temporarily unavailable')) {
    console.log('Circuit breaker: request rejected');
  }

  sleep(0.1);
}
```

## Troubleshooting

### Circuit Keeps Opening

**Symptoms**: Circuit breaker frequently transitions to open state

**Possible Causes**:
1. **Backend is genuinely unhealthy**
   - Check backend logs and metrics
   - Verify backend has sufficient resources
   - Check network connectivity

2. **Failure threshold too low**
   - Increase `failure_threshold` to tolerate transient errors
   - Increase `minimum_request_threshold` to require more data

3. **Timeout too aggressive**
   - Increase `proxy.timeout_ms` if backend is legitimately slow
   - Review backend response times

**Solution**:
```yaml
circuit_breaker:
  failure_threshold: 10    # Increase tolerance
  minimum_request_threshold: 5
  timeout_sec: 60          # Give more time to recover
```

### Circuit Never Opens

**Symptoms**: Backend is failing but circuit breaker stays closed

**Possible Causes**:
1. **Failures are 4xx** (client errors, which are ignored)
   - Check `fastgate_proxy_errors_total{error_type="timeout"}`
   - Verify errors are actually 5xx

2. **Not enough requests** to meet `minimum_request_threshold`
   - Lower threshold for low-traffic backends

3. **Circuit breaker disabled** in config
   - Check `circuit_breaker.enabled: true`

**Solution**:
```yaml
circuit_breaker:
  enabled: true
  failure_threshold: 3
  minimum_request_threshold: 2  # Lower for low traffic
```

### Circuit Opens But Backend is Healthy

**Symptoms**: Circuit breaker opens unnecessarily

**Possible Causes**:
1. **Transient network issues** causing false positives
2. **Backend slow to respond** triggering timeouts
3. **Too aggressive thresholds**

**Solution**:
```yaml
circuit_breaker:
  failure_threshold: 8      # More tolerant
  success_threshold: 1      # Recover faster
  timeout_sec: 20           # Shorter recovery window
  minimum_request_threshold: 5
```

### Circuit Flapping (Open → Closed → Open)

**Symptoms**: Circuit rapidly cycles between states

**Possible Causes**:
1. **Backend intermittently failing**
2. **Success threshold too low**
3. **Timeout too short** (tries recovery too soon)

**Solution**:
```yaml
circuit_breaker:
  success_threshold: 5      # Require more successes
  timeout_sec: 60           # Wait longer before retrying
  failure_threshold: 3      # Trip faster on failure
```

## Performance Impact

The circuit breaker is designed for **zero contention** in the hot path:

- **Closed state**: Single atomic load (`~5ns`)
- **Open state**: Timestamp comparison + atomic load (`~50ns`)
- **Half-open state**: Atomic increment + comparison (`~20ns`)

**Benchmark results** (Go 1.22, M1 Mac):
```
BenchmarkAllow-8                100000000    11.2 ns/op
BenchmarkRecordSuccess-8        50000000     28.5 ns/op
BenchmarkRecordFailure-8        30000000     42.1 ns/op
```

**Overhead**: <0.001% of total request latency (assuming 10ms+ requests)

## Multi-Origin Support

FastGate automatically creates separate circuit breakers for each backend origin:

```yaml
proxy:
  routes:
    - host: "api.example.com"
      origin: "http://api-backend:8080"     # Circuit breaker #1
    - host: "admin.example.com"
      origin: "http://admin-backend:9000"   # Circuit breaker #2
```

Each origin has independent state, thresholds, and metrics:
```promql
fastgate_proxy_circuit_state{origin="http://api-backend:8080"}      # 0 (closed)
fastgate_proxy_circuit_state{origin="http://admin-backend:9000"}    # 1 (open)
```

## Best Practices

### 1. Enable in Production
Circuit breakers are most valuable in production where cascading failures are costly:
```yaml
circuit_breaker:
  enabled: true  # Always enable in production
```

### 2. Start Conservative, Tune Based on Data
Begin with higher thresholds and lower them based on monitoring:
```yaml
# Start here
failure_threshold: 10
success_threshold: 2
timeout_sec: 60

# After observing behavior, tune to:
failure_threshold: 5  # Based on actual failure patterns
```

### 3. Monitor State Transitions
Track circuit breaker behavior in Grafana to understand backend health patterns.

### 4. Alert on Open Circuits
Create PagerDuty/Slack alerts for when circuits open:
```yaml
- alert: CriticalBackendDown
  expr: fastgate_proxy_circuit_state == 1
  for: 2m
  annotations:
    summary: "Backend {{ $labels.origin }} is down"
```

### 5. Combine with Health Checks
Use Kubernetes readiness probes + circuit breaker for defense-in-depth:
```yaml
readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
```

### 6. Test Failure Scenarios
Regularly test circuit breaker behavior in staging:
```bash
# Chaos testing
kubectl delete pod -l app=backend -n staging
# Observe circuit breaker behavior
```

## Comparison with Other Patterns

| Pattern | Use Case | FastGate Support |
|---------|----------|------------------|
| **Circuit Breaker** | Stop calling failing backends | ✅ Built-in (this doc) |
| **Retry with Backoff** | Transient errors | ⚠️ Manual (in client code) |
| **Timeout** | Prevent hanging requests | ✅ `proxy.timeout_ms` |
| **Rate Limiting** | Protect against overload | ✅ Built-in (policy) |
| **Bulkhead** | Isolate failures | ⚠️ Use K8s resource limits |

Circuit breakers complement these patterns - use them together for maximum resilience.

## References

- [Martin Fowler: Circuit Breaker](https://martinfowler.com/bliki/CircuitBreaker.html)
- [Release It!: Circuit Breaker Pattern](https://pragprog.com/titles/mnee2/release-it-second-edition/)
- [Hystrix: Circuit Breaker](https://github.com/Netflix/Hystrix/wiki/How-it-Works#CircuitBreaker)

## See Also

- [SECURITY.md](SECURITY.md) - Security best practices
- [k8s/README.md](k8s/README.md) - Kubernetes deployment
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
