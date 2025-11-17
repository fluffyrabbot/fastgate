# Testing WebAuthn Hardware Attestation

This guide explains how to test the WebAuthn (FIDO2) hardware attestation feature in FastGate.

## Prerequisites

### Hardware Requirements
You need a device with a **platform authenticator**:
- **macOS**: Touch ID (MacBook Pro/Air 2016+, iMac with Magic Keyboard)
- **Windows**: Windows Hello (TPM 2.0 chip required)
- **Linux**: TPM 2.0 chip (less common for browser support)
- **Mobile**: iOS Safari with Face ID/Touch ID, Android Chrome with fingerprint

### Browser Requirements
- **Chrome/Edge**: Full WebAuthn support
- **Firefox**: Full WebAuthn support
- **Safari**: Full WebAuthn support (macOS 14+, iOS 14+)

**Note**: Incognito/Private browsing may restrict platform authenticator access.

## Configuration

1. Enable WebAuthn in `config.example.yaml`:
   ```yaml
   webauthn:
     enabled: true
     rp_id: "localhost"       # Must match your domain
     rp_name: "FastGate"
     rp_origins:
       - "http://localhost:8088"
     ttl_sec: 60
   ```

2. For production domains, update `rp_id` and `rp_origins`:
   ```yaml
   rp_id: "example.com"      # No protocol, no port, no path
   rp_origins:
     - "https://example.com"
     - "https://www.example.com"
   ```

## Running the Test

### 1. Start the services
```bash
cd /home/user/fastgate
docker-compose up -d
```

This starts:
- **FastGate Decision Service** (port 8080)
- **Challenge Page** (served via NGINX on port 8088)
- **NGINX reverse proxy** (port 8088)

### 2. Trigger a challenge

Visit a protected endpoint without a clearance cookie:
```bash
curl -v http://localhost:8088/
```

You should get a **401 Unauthorized** response, indicating you need to solve a challenge.

### 3. Open the challenge page

Navigate to the challenge page in a WebAuthn-capable browser:
```
http://localhost:8088/challenge
```

### 4. Observe WebAuthn flow

**Expected behavior:**
1. Page shows: "Checking your connection..."
2. Browser prompts for platform authenticator:
   - macOS: "Touch ID" prompt
   - Windows: "Windows Hello" prompt
   - Mobile: "Face ID" or "Fingerprint" prompt
3. After authentication, you're redirected to `/` with a clearance cookie

**If WebAuthn fails or is unavailable:**
1. Page falls back to PoW (Proof-of-Work) challenge
2. Shows: "Solving challenge..." with SHA-256 computation
3. After solving, redirected with clearance cookie

### 5. Verify clearance cookie

Check the cookie in browser DevTools (Application → Cookies):
- **Name**: `Clearance`
- **Value**: JWT token (starts with `eyJ...`)
- **Path**: `/`
- **HttpOnly**: `true`
- **Secure**: `true`
- **MaxAge**: Depends on attestation tier:
  - **hardware_attested**: 24 hours (TPM, Touch ID, Windows Hello)
  - **attested**: 12 hours (packed format)
  - **low**: 6 hours (PoW fallback)

### 6. Decode the token

Use jwt.io or decode manually:
```bash
# Extract payload (second base64url segment)
TOKEN="<paste-your-token>"
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

**Expected payload:**
```json
{
  "iss": "fastgate",
  "exp": 1700000000,
  "iat": 1699913600,
  "tier": "hardware_attested"  // or "attested", "low"
}
```

### 7. Access protected resources

With the clearance cookie set, subsequent requests should succeed:
```bash
curl -b "Clearance=<your-token>" http://localhost:8088/
```

Expected: **200 OK** response

## Testing Different Attestation Formats

### Hardware-Backed (Tier: `hardware_attested`, 24h TTL)
- **TPM**: Windows Hello on devices with TPM 2.0
- **Apple**: Touch ID on macOS, Face ID/Touch ID on iOS
- **Android SafetyNet**: Android devices with hardware-backed keys

### Software-Backed (Tier: `attested`, 12h TTL)
- **Packed**: Generic attestation format (may be hardware or software)

### Fallback (Tier: `low`, 6h TTL)
- **PoW (SHA-256)**: Used when WebAuthn unavailable or fails

## Monitoring

### Backend Logs
```bash
docker-compose logs -f decision-service
```

**Expected log lines:**
```
WebAuthn enabled (RP ID: localhost, Origins: [http://localhost:8088])
WebAuthn endpoints registered: /v1/challenge/webauthn, /v1/challenge/complete/webauthn
```

### Metrics
Visit http://localhost:8080/metrics

**Key metrics:**
- `fastgate_challenge_started_total`: Increments when challenge issued
- `fastgate_challenge_solved_total`: Increments when PoW solved
- `fastgate_clearance_issued_total`: Increments when token issued
- `fastgate_authz_decision{decision="allow"}`: Increments on successful authz

## Troubleshooting

### "WebAuthn not supported" or immediate PoW fallback

**Possible causes:**
1. Browser doesn't support WebAuthn
   - Solution: Use Chrome, Firefox, or Safari

2. No platform authenticator available
   - Solution: Use a device with Touch ID, Windows Hello, or TPM

3. Incognito/Private browsing mode
   - Solution: Test in normal browsing mode

### "Attestation verification failed"

**Possible causes:**
1. RP ID mismatch
   - Solution: Ensure `rp_id` matches the domain (e.g., "localhost" for http://localhost:8088)

2. Origin mismatch
   - Solution: Add the full origin to `rp_origins` (e.g., "http://localhost:8088")

3. Challenge expired (TTL exceeded)
   - Solution: Increase `ttl_sec` in config, or complete challenge faster

### Browser console errors

**Check for:**
- CORS errors: Ensure NGINX proxy is configured correctly
- Mixed content: Use HTTPS in production
- DOM exceptions: Check browser support for `navigator.credentials.create()`

## Security Considerations

### Development vs Production

**Development (localhost):**
- RP ID: `"localhost"`
- Origins: `["http://localhost:8088"]`
- Secure cookie: Can be `false` for HTTP

**Production:**
- RP ID: Your domain (e.g., `"example.com"`)
- Origins: HTTPS URLs only
- Secure cookie: **MUST** be `true`
- HTTPS required for WebAuthn (browser restriction)

### Privacy Pass Attestation (Future)

The current implementation uses direct attestation (we receive the TPM/Apple certificate chain). For privacy-preserving attestation, Phase 1 includes a placeholder for Privacy Pass integration:

```go
// decision-service/cmd/fastgate/main.go:48-54
// TODO: Implement Privacy Pass attestation
```

This will allow devices to prove attestation without revealing hardware identifiers.

## Next Steps

After verifying WebAuthn works:
1. ✅ **Phase 1 Complete**: Hardware-backed attestation
2. **Phase 2**: Federated threat intelligence (STIX/TAXII)
3. **Phase 3**: Behavioral entropy fingerprinting
4. **Phase 4**: Zero-knowledge proof challenges

See `docs/plans/ROADMAP.md` for the full innovation plan.
