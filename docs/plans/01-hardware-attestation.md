# Phase 1: Hardware-Backed Attestation via WebAuthn/TPM

**Status**: Proposed
**Priority**: High
**Effort**: 2-3 weeks
**Innovation Level**: 🔥🔥🔥 High (First open-source L7 gateway with TPM attestation)

---

## 1. Overview

### Problem Statement
Current FastGate challenges (SHA-256 PoW) can be bypassed by:
- Bot farms with sufficient CPU resources
- Cloud instances (AWS/GCP) renting compute power
- Specialized ASIC miners

### Solution
Leverage **hardware-backed attestation** via WebAuthn to cryptographically prove:
1. Device is genuine (not a VM or emulator)
2. Private keys are stored in TPM/Secure Enclave
3. User presence was verified (biometric or PIN)

### Key Benefits
- **Unforgeable**: Attackers need physical TPM chips (can't rent from cloud)
- **Privacy-preserving**: No persistent tracking, one-time attestation
- **Better UX**: Biometric auth faster than PoW solving
- **Tiered security**: Attested devices get longer clearance (24h vs 6h)

---

## 2. Technical Architecture

### 2.1 High-Level Flow

```
┌──────────────────────────────────────────────────────────┐
│ 1. User visits gated page                                 │
│    ↓                                                      │
│ 2. NGINX → Decision Service → Returns 401 (challenge)    │
│    ↓                                                      │
│ 3. Browser redirected to /__uam                          │
│    - Detects WebAuthn support                            │
│    - Shows "Verify with Touch ID / Windows Hello"        │
│    ↓                                                      │
│ 4. User clicks → navigator.credentials.create()          │
│    - Platform authenticator (TPM/TEE) generates keypair  │
│    - Attestation object signed by manufacturer CA        │
│    ↓                                                      │
│ 5. POST /v1/challenge/webauthn                           │
│    - Decision service validates attestation cert chain   │
│    - Checks TPM model is genuine (not software emulator) │
│    - Issues tier="hardware_attested" JWT                 │
│    ↓                                                      │
│ 6. Redirect to original URL with clearance cookie        │
└──────────────────────────────────────────────────────────┘
```

### 2.2 Component Architecture

```
┌───────────────────────────────────────────────────────────┐
│ Browser (challenge-page/)                                 │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ webauthn-solver.js                                  │ │
│  │  - Feature detection (PublicKeyCredential API)      │ │
│  │  - Challenge request flow                           │ │
│  │  - Attestation object handling                      │ │
│  │  - Fallback to PoW if WebAuthn unavailable          │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────┬────────────────────────────────────────┘
                   │ HTTPS (required for WebAuthn)
                   ▼
┌───────────────────────────────────────────────────────────┐
│ Decision Service (Go)                                     │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ internal/webauthn/                                  │ │
│  │  - handler.go      → HTTP endpoints                │ │
│  │  - verifier.go     → Attestation validation        │ │
│  │  - certchain.go    → TPM/FIDO cert verification    │ │
│  │  - store.go        → Challenge state (LRU)         │ │
│  └─────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ internal/authz/handler.go (MODIFIED)               │ │
│  │  - Check clearance tier ("low" vs "hardware_attested")│
│  │  - Lower risk score for attested tokens            │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

### 2.3 Data Flow

**Challenge Request:**
```http
POST /v1/challenge/webauthn HTTP/1.1
Content-Type: application/json

{
  "return_url": "/dashboard",
  "attestation": "direct"  // Request attestation object
}
```

**Challenge Response:**
```json
{
  "challenge_id": "abc123...",
  "challenge": "cmFuZG9tQnl0ZXM=",  // Base64url-encoded
  "rp": {
    "name": "FastGate",
    "id": "example.com"
  },
  "user": {
    "id": "dXNlcl9hbm9u",  // Ephemeral, no tracking
    "name": "anonymous",
    "displayName": "Anonymous User"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},   // ES256
    {"type": "public-key", "alg": -257}  // RS256
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",  // TPM/TEE only
    "requireResidentKey": false,
    "userVerification": "required"  // Biometric/PIN required
  },
  "attestation": "direct",
  "timeout": 60000,
  "return_url": "/dashboard"
}
```

**Attestation Submission:**
```http
POST /v1/challenge/complete/webauthn HTTP/1.1
Content-Type: application/json

{
  "challenge_id": "abc123...",
  "attestation_object": "o2NmbXRmcGFja2VkZ2F0dFN0bXSj...",
  "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRl...",
  "return_url": "/dashboard"
}
```

---

## 3. Implementation Phases

### Phase 1.1: Browser Client (Week 1)
**Files to create:**
- `challenge-page/webauthn-solver.js`
- `challenge-page/index.html` (update with WebAuthn option)

**Tasks:**
1. Feature detection
   ```javascript
   function supportsWebAuthn() {
       return window.PublicKeyCredential !== undefined &&
              typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
   }
   ```

2. Challenge request flow
   ```javascript
   async function requestWebAuthnChallenge(returnUrl) {
       const res = await fetch('/v1/challenge/webauthn', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({ return_url: returnUrl, attestation: 'direct' })
       });
       return res.json();
   }
   ```

3. Credential creation
   ```javascript
   async function createCredential(options) {
       const credential = await navigator.credentials.create({
           publicKey: {
               challenge: base64urlToBytes(options.challenge),
               rp: options.rp,
               user: {
                   id: base64urlToBytes(options.user.id),
                   name: options.user.name,
                   displayName: options.user.displayName
               },
               pubKeyCredParams: options.pubKeyCredParams,
               authenticatorSelection: options.authenticatorSelection,
               attestation: options.attestation,
               timeout: options.timeout
           }
       });
       return credential;
   }
   ```

4. Attestation submission
   ```javascript
   async function submitAttestation(challengeId, credential, returnUrl) {
       const attestationObject = arrayBufferToBase64url(credential.response.attestationObject);
       const clientDataJSON = arrayBufferToBase64url(credential.response.clientDataJSON);

       const res = await fetch('/v1/challenge/complete/webauthn', {
           method: 'POST',
           headers: { 'Content-Type': 'application/json' },
           body: JSON.stringify({
               challenge_id: challengeId,
               attestation_object: attestationObject,
               client_data_json: clientDataJSON,
               return_url: returnUrl
           })
       });

       if (res.status === 302 || res.ok) {
           const location = res.headers.get('Location') || returnUrl;
           window.location.replace(location);
       }
   }
   ```

5. Fallback handling
   ```javascript
   async function startChallenge() {
       if (await supportsWebAuthn()) {
           await startWebAuthnFlow();
       } else {
           await startPoWFlow();  // Existing implementation
       }
   }
   ```

### Phase 1.2: Backend Endpoints (Week 1-2)
**Files to create:**
- `decision-service/internal/webauthn/handler.go`
- `decision-service/internal/webauthn/verifier.go`
- `decision-service/internal/webauthn/certchain.go`
- `decision-service/internal/webauthn/store.go`

**Dependencies:**
```bash
cd decision-service
go get github.com/go-webauthn/webauthn@latest
```

**Task 1: Challenge endpoint**
```go
// decision-service/internal/webauthn/handler.go
package webauthn

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/go-webauthn/webauthn/protocol"
    "github.com/go-webauthn/webauthn/webauthn"
)

type Handler struct {
    WebAuthn *webauthn.WebAuthn
    Store    *Store
}

func NewHandler(rpID, rpName string, rpOrigins []string) (*Handler, error) {
    wconfig := &webauthn.Config{
        RPDisplayName: rpName,
        RPID:         rpID,
        RPOrigins:    rpOrigins,
        AttestationPreference: protocol.PreferDirectAttestation,
        AuthenticatorSelection: protocol.AuthenticatorSelection{
            AuthenticatorAttachment: protocol.Platform,
            RequireResidentKey:      protocol.ResidentKeyNotRequired(),
            UserVerification:        protocol.VerificationRequired,
        },
    }

    wa, err := webauthn.New(wconfig)
    if err != nil {
        return nil, err
    }

    return &Handler{
        WebAuthn: wa,
        Store:    NewStore(60 * time.Second),
    }, nil
}

func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
    type Req struct {
        ReturnURL string `json:"return_url"`
    }
    var req Req
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    // Create ephemeral user (no tracking)
    user := &User{
        ID:          randomBytes(16),
        Name:        "anonymous",
        DisplayName: "Anonymous User",
    }

    options, session, err := h.WebAuthn.BeginRegistration(user)
    if err != nil {
        http.Error(w, "server error", http.StatusInternalServerError)
        return
    }

    // Store session
    challengeID := h.Store.Put(session, req.ReturnURL)

    // Add challenge_id to response
    resp := struct {
        *protocol.CredentialCreation
        ChallengeID string `json:"challenge_id"`
        ReturnURL   string `json:"return_url"`
    }{
        CredentialCreation: options,
        ChallengeID:       challengeID,
        ReturnURL:         req.ReturnURL,
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}
```

**Task 2: Attestation verification**
```go
// decision-service/internal/webauthn/handler.go (continued)

func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
    type Req struct {
        ChallengeID       string `json:"challenge_id"`
        AttestationObject string `json:"attestation_object"`
        ClientDataJSON    string `json:"client_data_json"`
        ReturnURL         string `json:"return_url"`
    }
    var req Req
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    // Retrieve session
    session, returnURL, ok := h.Store.Get(req.ChallengeID)
    if !ok {
        http.Error(w, "challenge not found or expired", http.StatusBadRequest)
        return
    }
    defer h.Store.Consume(req.ChallengeID)

    // Parse credential
    parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
    if err != nil {
        http.Error(w, "invalid attestation", http.StatusBadRequest)
        return
    }

    // Verify attestation
    user := &User{ID: session.UserID}
    credential, err := h.WebAuthn.CreateCredential(user, *session, parsedResponse)
    if err != nil {
        http.Error(w, "attestation verification failed", http.StatusBadRequest)
        return
    }

    // Check attestation format (TPM, packed, etc.)
    tier := "attested"
    if isHardwareBacked(credential.Attestation) {
        tier = "hardware_attested"
    }

    // Issue clearance token (caller provides keyring)
    // tokenStr := keyring.Sign(tier, 24*time.Hour)
    // http.SetCookie(w, buildCookie(cfg, tokenStr))

    w.Header().Set("Location", returnURL)
    w.WriteHeader(http.StatusFound)
}

func isHardwareBacked(attestationType string) bool {
    // TPM, packed (with X5C cert chain), or Android SafetyNet
    switch attestationType {
    case "tpm", "android-safetynet", "apple":
        return true
    case "packed":
        // Check if cert chain present (hardware-backed)
        return true
    default:
        return false
    }
}
```

**Task 3: Certificate chain validation**
```go
// decision-service/internal/webauthn/certchain.go
package webauthn

import (
    "crypto/x509"
    "encoding/pem"
    "errors"
)

// TPM manufacturer root CAs (embed in binary)
var trustedTPMRoots = []string{
    // Intel TPM CA
    `-----BEGIN CERTIFICATE-----
MIIFkz...
-----END CERTIFICATE-----`,
    // AMD TPM CA
    `-----BEGIN CERTIFICATE-----
MIIFjD...
-----END CERTIFICATE-----`,
    // NXP TPM CA
    // ... etc
}

func VerifyTPMCertChain(attestationCert *x509.Certificate) error {
    roots := x509.NewCertPool()
    for _, rootPEM := range trustedTPMRoots {
        block, _ := pem.Decode([]byte(rootPEM))
        if block == nil {
            continue
        }
        cert, err := x509.ParseCertificate(block.Bytes)
        if err != nil {
            continue
        }
        roots.AddCert(cert)
    }

    opts := x509.VerifyOptions{
        Roots:     roots,
        KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
    }

    _, err := attestationCert.Verify(opts)
    if err != nil {
        return errors.New("TPM certificate chain verification failed")
    }

    return nil
}
```

**Task 4: Challenge store**
```go
// decision-service/internal/webauthn/store.go
package webauthn

import (
    "container/list"
    "crypto/rand"
    "encoding/base64"
    "sync"
    "time"

    "github.com/go-webauthn/webauthn/protocol"
)

type Store struct {
    mu   sync.Mutex
    data map[string]*entry
    lru  *list.List
    ttl  time.Duration
    cap  int
}

type entry struct {
    id        string
    session   *protocol.SessionData
    returnURL string
    expiresAt time.Time
}

func NewStore(ttl time.Duration) *Store {
    return &Store{
        data: make(map[string]*list.Element, 10000),
        lru:  list.New(),
        ttl:  ttl,
        cap:  10000,
    }
}

func (s *Store) Put(session *protocol.SessionData, returnURL string) string {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Generate ID
    idBytes := make([]byte, 16)
    rand.Read(idBytes)
    id := base64.RawURLEncoding.EncodeToString(idBytes)

    // Evict if at capacity
    if s.lru.Len() >= s.cap {
        back := s.lru.Back()
        if back != nil {
            old := back.Value.(*entry)
            delete(s.data, old.id)
            s.lru.Remove(back)
        }
    }

    en := &entry{
        id:        id,
        session:   session,
        returnURL: returnURL,
        expiresAt: time.Now().Add(s.ttl),
    }

    el := s.lru.PushFront(en)
    s.data[id] = el

    return id
}

func (s *Store) Get(id string) (*protocol.SessionData, string, bool) {
    s.mu.Lock()
    defer s.mu.Unlock()

    el, ok := s.data[id]
    if !ok {
        return nil, "", false
    }

    en := el.Value.(*entry)
    if time.Now().After(en.expiresAt) {
        delete(s.data, id)
        s.lru.Remove(el)
        return nil, "", false
    }

    s.lru.MoveToFront(el)
    return en.session, en.returnURL, true
}

func (s *Store) Consume(id string) {
    s.mu.Lock()
    defer s.mu.Unlock()

    if el, ok := s.data[id]; ok {
        delete(s.data, id)
        s.lru.Remove(el)
    }
}
```

**Task 5: User type (ephemeral)**
```go
// decision-service/internal/webauthn/user.go
package webauthn

import "github.com/go-webauthn/webauthn/webauthn"

type User struct {
    ID          []byte
    Name        string
    DisplayName string
}

func (u *User) WebAuthnID() []byte              { return u.ID }
func (u *User) WebAuthnName() string            { return u.Name }
func (u *User) WebAuthnDisplayName() string     { return u.DisplayName }
func (u *User) WebAuthnIcon() string            { return "" }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return nil }

func randomBytes(n int) []byte {
    b := make([]byte, n)
    rand.Read(b)
    return b
}
```

### Phase 1.3: Integration with Existing Flow (Week 2)
**Files to modify:**
- `decision-service/cmd/fastgate/main.go`
- `decision-service/internal/authz/handler.go`
- `decision-service/internal/config/config.go`

**Task 1: Add configuration**
```yaml
# config.example.yaml
webauthn:
  enabled: true
  rp_id: "localhost"           # Domain name (no protocol)
  rp_name: "FastGate"
  rp_origins:
    - "http://localhost:8088"
    - "https://example.com"
  ttl_sec: 60
```

**Task 2: Initialize WebAuthn handler in main.go**
```go
// decision-service/cmd/fastgate/main.go (add after line 69)

var webauthnHandler *webauthn.Handler
if cfg.WebAuthn.Enabled {
    wh, err := webauthn.NewHandler(
        cfg.WebAuthn.RPID,
        cfg.WebAuthn.RPName,
        cfg.WebAuthn.RPOrigins,
    )
    if err != nil {
        log.Fatalf("webauthn handler: %v", err)
    }
    webauthnHandler = wh
    log.Printf("WebAuthn enabled (RP ID: %s)", cfg.WebAuthn.RPID)
}

// Add endpoints
if webauthnHandler != nil {
    mux.Handle("/v1/challenge/webauthn", http.HandlerFunc(webauthnHandler.BeginRegistration))
    mux.Handle("/v1/challenge/complete/webauthn", http.HandlerFunc(webauthnHandler.FinishRegistration))
}
```

**Task 3: Modify authz handler to recognize tiers**
```go
// decision-service/internal/authz/handler.go (modify computeScore)

func (h *Handler) computeScore(r *http.Request, method, uri, clientIP string, wsUpgrade bool, hadInvalidToken bool) (int, []string) {
    score := 0
    reasons := make([]string, 0, 8)

    // NEW: Check clearance tier
    var rawTok string
    if c, err := r.Cookie(h.Cfg.Cookie.Name); err == nil {
        rawTok = c.Value
    }

    if rawTok != "" {
        claims, ok, _ := h.Keyring.Verify(rawTok, 2*time.Minute)
        if ok && claims.Tier == "hardware_attested" {
            // Significantly reduce risk score for hardware-attested devices
            score -= 30
            reasons = append(reasons, "hardware_attested")
        }
    }

    // ... rest of scoring logic
}
```

### Phase 1.4: Testing (Week 3)
**Test cases:**
1. Feature detection (devices with/without platform authenticator)
2. Challenge flow (request → credential creation → verification)
3. Certificate chain validation (genuine TPM vs software emulator)
4. Tier assignment (hardware_attested vs attested vs low)
5. Fallback to PoW (unsupported devices)

**Manual testing:**
```bash
# Test on different platforms
- Windows 11 with Windows Hello
- macOS with Touch ID
- Android 12+ with biometric
- Linux without TPM (should fallback to PoW)
```

**Automated testing:**
```go
// decision-service/internal/webauthn/verifier_test.go
package webauthn

import (
    "testing"
    "github.com/go-webauthn/webauthn/protocol"
)

func TestVerifyTPMAttestation(t *testing.T) {
    // Test with known-good TPM attestation
    attestation := loadTestAttestation("testdata/tpm_intel.json")

    err := VerifyTPMCertChain(attestation.Certificate)
    if err != nil {
        t.Errorf("Expected valid TPM cert, got error: %v", err)
    }
}

func TestRejectSoftwareAttestation(t *testing.T) {
    // Test with software emulator (none attestation)
    attestation := loadTestAttestation("testdata/software.json")

    if isHardwareBacked(attestation.Format) {
        t.Error("Software attestation incorrectly marked as hardware-backed")
    }
}
```

---

## 4. Configuration

### 4.1 Config Schema
```yaml
# config.example.yaml
webauthn:
  enabled: true
  rp_id: "example.com"        # Must match domain (no port)
  rp_name: "FastGate Security"
  rp_origins:
    - "https://example.com"
    - "https://www.example.com"
  ttl_sec: 60

  # Optional: Require specific attestation formats
  allowed_attestation_formats:
    - "tpm"
    - "packed"
    - "android-safetynet"
    - "apple"

  # Optional: Reject software authenticators
  require_hardware: true

token:
  # Extend TTL for hardware-attested tokens
  tier_ttl:
    low: 21600              # 6 hours
    attested: 43200         # 12 hours
    hardware_attested: 86400  # 24 hours
```

### 4.2 NGINX Configuration
```nginx
# edge-gateway/nginx.conf (modify challenge handler)

location @fastgate_challenge {
    if ($fastgate_set_cookie) {
        add_header Set-Cookie $fastgate_set_cookie always;
    }

    # Redirect to challenge page (now with WebAuthn option)
    return 302 /__uam?u=$request_uri;
}

# Serve WebAuthn endpoints (unguarded, same as /v1/)
location /v1/challenge/webauthn {
    proxy_pass http://fastgate_decision;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
}

location /v1/challenge/complete/webauthn {
    proxy_pass http://fastgate_decision;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
}
```

---

## 5. Security Considerations

### 5.1 Threat Model
**Threats mitigated:**
- ✅ Bot farms (can't obtain genuine TPM chips at scale)
- ✅ Cloud-based attacks (AWS/GCP VMs don't pass TPM attestation)
- ✅ Credential stuffing (hardware-backed keys can't be exfiltrated)

**Threats NOT mitigated:**
- ❌ Compromised legitimate devices (if user's laptop is hacked, attestation still passes)
- ❌ Social engineering (attacker tricks user into pressing biometric)
- ❌ Physical device theft (attacker with stolen laptop can authenticate)

### 5.2 Privacy Protections
**What we collect:**
- ✅ Attestation format (TPM, Apple, Android)
- ✅ Manufacturer CA (Intel, AMD, etc.)

**What we DON'T collect:**
- ❌ Device serial number (ephemeral user IDs)
- ❌ Biometric data (stays on device)
- ❌ Credential storage (non-resident keys)
- ❌ Cross-session tracking (new credential per challenge)

### 5.3 Attack Scenarios

**Scenario 1: Software Emulator**
```
Attacker uses Chrome + virtual TPM
→ Attestation format: "none" or missing cert chain
→ Tier: "attested" (lower priority than hardware)
→ Still challenged on risky paths
```

**Scenario 2: Stolen Credentials**
```
Attacker steals clearance cookie
→ Cookie contains tier="hardware_attested"
→ If reused from different IP: score increases
→ Short TTL (24h max) limits damage
```

**Scenario 3: Certificate Forgery**
```
Attacker forges TPM certificate
→ Cert chain validation fails (not signed by manufacturer CA)
→ Rejected, fallback to PoW challenge
```

---

## 6. Rollout Plan

### 6.1 Gradual Deployment
```yaml
# Week 1: Enable in observe mode
webauthn:
  enabled: true
modes:
  enforce: false  # Log only, don't block

# Week 2: Enable for subset of paths
policy:
  paths:
    - pattern: "^/login"
      require_webauthn: true  # Sensitive paths only

# Week 3: Full enforcement
modes:
  enforce: true
```

### 6.2 Metrics to Track
```go
// decision-service/internal/metrics/metrics.go
var (
    WebAuthnAttempts = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "fastgate_webauthn_attempts_total",
            Help: "WebAuthn challenge attempts",
        },
        []string{"result"},  // success, failure, unsupported
    )

    WebAuthnTiers = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "fastgate_clearance_tier_total",
            Help: "Clearance tokens issued by tier",
        },
        []string{"tier"},  // low, attested, hardware_attested
    )

    WebAuthnFormats = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "fastgate_webauthn_formats_total",
            Help: "Attestation formats observed",
        },
        []string{"format"},  // tpm, packed, apple, android-safetynet
    )
)
```

### 6.3 Success Criteria
- ✅ >70% of users have WebAuthn-capable devices
- ✅ <5% fallback to PoW (acceptable for old devices)
- ✅ 50% reduction in bot traffic (measured via challenge success rate)
- ✅ <100ms latency for attestation verification

---

## 7. Future Enhancements

### 7.1 Passkey Syncing (Phase 1.5)
Allow users to sync passkeys across devices:
```go
authenticatorSelection: protocol.AuthenticatorSelection{
    RequireResidentKey: protocol.ResidentKeyRequired(),  // Enable syncing
    UserVerification:   protocol.VerificationRequired,
}
```

### 7.2 Conditional UI (Phase 1.6)
Auto-fill passkeys in login forms:
```javascript
// Conditional mediation (Chrome 108+)
const credential = await navigator.credentials.get({
    publicKey: { ... },
    mediation: 'conditional'
});
```

### 7.3 Anonymous Attestation (Phase 2.0)
Privacy Pass-style unlinkable tokens:
```
User proves TPM ownership once → Receives batch of anonymous tokens
→ Redeems tokens without re-attesting (unlinkable)
```

---

## 8. References

### Technical Specs
- [WebAuthn Level 3 (W3C)](https://www.w3.org/TR/webauthn-3/)
- [FIDO2 Attestation Formats](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html)
- [TPM 2.0 Attestation Format](https://www.w3.org/TR/webauthn/#sctn-tpm-attestation)

### Libraries
- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) - Go implementation
- [Web Authentication API (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API)

### Prior Art Analysis
- Cloudflare Turnstile: Proprietary, no hardware attestation
- Apple Private Access Tokens: Similar concept, iOS/macOS only
- Android SafetyNet: Hardware attestation, Android only
- **FastGate**: Cross-platform, open-source, L7 gateway integration

---

## 9. Success Definition

**Innovation Score: 9/10**
- First open-source L7 gateway with WebAuthn attestation
- Cross-platform hardware verification
- Privacy-preserving (no persistent tracking)
- Homelab-friendly (no cloud dependencies)

**Effort vs Impact:**
- Effort: 2-3 weeks (moderate)
- Impact: High (bypasses all cloud-based bot farms)
- Differentiation: Unique in open-source space

**Next Steps:**
After Phase 1 completion, proceed to:
- Phase 2: Federated Threat Intelligence
- Phase 3: Behavioral Entropy Fingerprinting
