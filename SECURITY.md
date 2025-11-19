# FastGate Security Guide

## Overview

FastGate is a Layer 7 DDoS protection gateway that combines multiple security mechanisms:
- **WebAuthn** - Hardware-backed authentication
- **Proof-of-Work Challenges** - Computational cost for requests
- **Threat Intelligence** - Federated indicator sharing (STIX/TAXII 2.1)
- **Rate Limiting** - Per-IP and per-token request throttling
- **IP Binding** - Trusted proxy validation

## Production Deployment Security Checklist

### 1. Generate Production Secrets (CRITICAL)

**Never use the default test keys in production.** Generate unique secrets:

```bash
# Generate cluster secret (for gossip encryption)
openssl rand -base64 32

# Generate token signing secret
openssl rand -base64 32
```

Update `config.production.yaml`:
```yaml
token:
  keys:
    v1: "YOUR_GENERATED_SECRET_HERE"

cluster:
  secret_key: "YOUR_GENERATED_SECRET_HERE"
```

### 2. Configure Trusted Proxies (CRITICAL)

If FastGate runs behind a load balancer or reverse proxy, configure trusted proxy CIDRs to prevent IP spoofing attacks:

```yaml
server:
  trusted_proxies:
    - "10.0.0.0/8"       # Internal VPC
    - "172.16.0.0/12"    # Load balancer subnet
```

**Without this configuration**, attackers can spoof `X-Forwarded-For` headers to bypass rate limiting.

#### Finding Your Proxy IPs

**AWS ALB/NLB:**
```bash
aws ec2 describe-network-interfaces --filters "Name=description,Values=*ELB*" \
  --query 'NetworkInterfaces[*].PrivateIpAddresses[*].PrivateIpAddress'
```

**GCP Load Balancer:**
```bash
gcloud compute forwarding-rules list --format="value(IPAddress)"
```

**NGINX/HAProxy:**
```bash
# Check the actual connecting IP
grep "X-Forwarded-For" /var/log/nginx/access.log | awk '{print $1}' | sort -u
```

### 3. Enable TLS (CRITICAL)

```yaml
server:
  tls_enabled: true
  tls_cert_file: "/etc/fastgate/tls/cert.pem"
  tls_key_file: "/etc/fastgate/tls/key.pem"

cookie:
  secure: true  # Requires TLS
```

#### Obtaining Certificates

**Let's Encrypt (Recommended):**
```bash
certbot certonly --standalone -d example.com
```

**Self-Signed (Development Only):**
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 4. WebAuthn Configuration

```yaml
webauthn:
  enabled: true
  rp_id: "example.com"           # MUST match your domain
  rp_name: "Example Application"
  rp_origins:
    - "https://example.com"      # MUST use HTTPS in production
```

**Security Notes:**
- `rp_id` must match the domain serving FastGate
- Origins must use HTTPS (browsers reject WebAuthn over HTTP except localhost)
- Attestation is validated against the WebAuthn specification

### 5. Challenge Configuration

```yaml
challenge:
  difficulty_bits: 16  # Higher = harder (12-20 recommended)
  ttl_sec: 60          # Challenge validity window
  nonce_rps_limit: 5.0 # Per-IP challenge request rate limit
```

**Difficulty Guidelines:**
- **12 bits**: ~4ms on modern CPU (development)
- **16 bits**: ~60ms (production, light protection)
- **18 bits**: ~250ms (under attack)
- **20 bits**: ~1s (extreme DDoS)

### 6. Policy Tuning

```yaml
policy:
  challenge_threshold: 30   # Score >= 30 triggers challenge
  block_threshold: 100      # Score >= 100 blocks immediately
  ip_rps_threshold: 100     # Requests per 10s per IP

  paths:
    - pattern: "^/api/admin"
      base: 20  # High-value endpoints get base score
```

**Risk Score Components:**
- Path base: 0-50 (configured per path)
- Mutating methods (POST/PUT/DELETE): +15
- WebSocket upgrade: +10
- Missing User-Agent: +15
- Headless User-Agent: +15
- Missing Accept-Language: +10
- Invalid/expired token: +10
- IP RPS exceeded: +0-30 (proportional)
- Threat Intel match: +0-50 (based on confidence)
- Under Attack mode: +15

## Security Features

### Implemented Protections

✅ **Challenge Replay Prevention** - Challenges consumed before verification
✅ **Origin Validation** - Explicit origin checks for WebAuthn
✅ **Request Smuggling Detection** - Dual Content-Length/Transfer-Encoding headers rejected
✅ **Open Redirect Prevention** - URL decoding to prevent encoding bypasses
✅ **Constant-Time Crypto** - Prevents timing side-channel attacks
✅ **Goroutine Leak Prevention** - Timers cleaned up on shutdown
✅ **Content-Length Validation** - Body size checked before reading
✅ **JWT Algorithm Validation** - "none" algorithm explicitly rejected
✅ **Security Headers** - CSP, X-Frame-Options, HSTS, X-Content-Type-Options
✅ **Rate Limiter Monitoring** - Alerts at 90% capacity

### Defense-in-Depth Layers

1. **Network Layer**: Trusted proxy validation, IP-based rate limiting
2. **Application Layer**: Challenge/response, risk scoring, JWT validation
3. **Authentication Layer**: WebAuthn with hardware attestation
4. **Intelligence Layer**: TAXII threat feed integration

## Threat Model

### In Scope

- **Layer 7 DDoS**: High request rate attacks, application-level floods
- **Credential Stuffing**: Automated login attempts
- **Bot Traffic**: Scrapers, vulnerability scanners
- **Account Takeover**: Unauthorized access attempts

### Out of Scope

- **Layer 3/4 DDoS**: Network floods (use cloud DDoS protection)
- **Zero-Day Vulnerabilities**: In upstream applications (use WAF)
- **Physical Security**: Server access (use datacenter security)
- **Social Engineering**: Phishing, pretexting (use security awareness training)

## Attack Scenarios & Mitigations

### Scenario 1: High Request Rate DDoS

**Attack**: Attacker floods server with 10,000 req/s from botnet
**Mitigation**:
1. IP RPS limiter triggers at configured threshold (e.g., 100 req/10s)
2. Risk score increases, challenge triggered
3. Bots fail PoW challenge (16 bits = ~60ms each)
4. Effective rate reduced to ~17 req/s per bot
5. Threat intel publishes attacker IPs to peer nodes

### Scenario 2: IP Spoofing to Bypass Rate Limiting

**Attack**: Attacker spoofs `X-Forwarded-For` header
**Without Trusted Proxies**: ❌ Attack succeeds, rate limiting bypassed
**With Trusted Proxies**: ✅ XFF ignored from untrusted source, real IP used

### Scenario 3: WebAuthn Attestation Bypass

**Attack**: Attacker attempts to register with software authenticator
**Mitigation**:
1. Attestation format validated (packed, fido-u2f, etc.)
2. Test authenticators rejected if using known test AAGUID
3. Origin strictly validated against configured `rp_origins`
4. Challenge consumed before verification (prevents replay)

### Scenario 4: Request Smuggling

**Attack**: Dual `Content-Length` and `Transfer-Encoding` headers
**Mitigation**: Request rejected with warning log before proxying

### Scenario 5: Open Redirect via Challenge Return URL

**Attack**: `return_url=//evil.com` or `return_url=%2F%2Fevil.com`
**Mitigation**: URL decoded and validated to ensure path-only, same-origin redirect

## Configuration Security

### Environment-Based Secrets (Recommended)

Instead of storing secrets in config files, use environment variables:

```bash
export FASTGATE_TOKEN_SECRET=$(openssl rand -base64 32)
export FASTGATE_CLUSTER_SECRET=$(openssl rand -base64 32)
```

Update config loader to read from environment (custom implementation required).

### File Permissions

```bash
chmod 600 config.production.yaml      # Only owner can read
chown fastgate:fastgate config.production.yaml
```

### Secrets Management

**Kubernetes:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: fastgate-secrets
type: Opaque
data:
  token-secret: <base64-encoded-secret>
  cluster-secret: <base64-encoded-secret>
```

**HashiCorp Vault:**
```bash
vault kv put secret/fastgate/prod \
  token_secret=$(openssl rand -base64 32) \
  cluster_secret=$(openssl rand -base64 32)
```

## Monitoring & Alerting

### Critical Metrics to Monitor

```promql
# Rate limit hits (potential attack)
rate(fastgate_rate_limit_hits_total[5m]) > 100

# High block rate (active attack)
rate(fastgate_authz_decision_total{action="block"}[5m]) > 50

# Challenge solve rate (bot detection effectiveness)
fastgate_challenge_solved_total / fastgate_challenge_started_total < 0.5

# High error rate (potential issue)
rate(fastgate_proxy_errors_total[5m]) > 10
```

### Security Events to Log

- All `block` decisions with full context
- Rate limit violations
- WebAuthn registration failures
- Challenge validation failures
- Threat intel matches

## Incident Response

### During Active Attack

1. **Enable Under Attack Mode**:
   ```yaml
   modes:
     under_attack: true  # Adds +15 to all risk scores
   ```

2. **Increase Challenge Difficulty**:
   ```yaml
   challenge:
     difficulty_bits: 20  # ~1s per challenge
   ```

3. **Lower Thresholds**:
   ```yaml
   policy:
     challenge_threshold: 20  # More aggressive
   ```

4. **Review Logs**:
   ```bash
   kubectl logs -f deployment/fastgate | grep "decision=block"
   ```

### Post-Incident

1. Export threat intel indicators
2. Share with TAXII peers
3. Review policy effectiveness
4. Update scoring weights if needed

## Compliance Considerations

### GDPR

- IP addresses are logged (consider data minimization)
- WebAuthn credentials are hardware-bound (no PII stored)
- Implement data retention policy for logs

### PCI DSS

- TLS required (Requirement 4.1)
- Strong cryptography (Requirement 3.5/3.6)
- Access control via WebAuthn (Requirement 8.3)
- Logging and monitoring (Requirement 10)

## Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

Contact: security@yourcompany.com (update this)

Include:
- Detailed description
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Audit History

- **2025-11-19**: Comprehensive security audit (Grade: A)
  - 9 critical fixes implemented
  - Test key validation enforced
  - Trusted proxy validation added
  - Constant-time crypto implemented

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [STIX/TAXII 2.1](https://oasis-open.github.io/cti-documentation/)
- [Proof-of-Work Best Practices](https://tools.ietf.org/html/rfc8374)
