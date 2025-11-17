# Phase 2: Federated Threat Intelligence Network

**Status**: Proposed
**Priority**: Medium-High
**Effort**: 1-2 weeks
**Innovation Level**: 🔥🔥 Medium-High (First decentralized threat sharing for L7 gateways)

---

## 1. Overview

### Problem Statement
Current FastGate instances operate in isolation:
- Each deployment fights bots independently
- Attack patterns discovered on one instance don't benefit others
- No collective defense mechanism

Commercial solutions (Cloudflare, Akamai) have centralized threat intel, but:
- Walled gardens (can't share between providers)
- No visibility into what's being shared
- Privacy concerns (all data flows to vendor)

### Solution
Build a **decentralized threat-sharing mesh** using STIX/TAXII standards where:
- FastGate instances share attack indicators in real-time
- Privacy-preserving (only share anonymized patterns, not raw logs)
- Peer-to-peer or hub-based topology
- Open protocol (compatible with other STIX/TAXII feeds)

### Key Benefits
- **Collective defense**: Homelab community helps each other
- **Faster response**: Block IPs/patterns within seconds of first sighting
- **Open ecosystem**: Compatible with AlienVault OTX, MISP, OpenCTI
- **Privacy-first**: Operators control what they share

---

## 2. Technical Architecture

### 2.1 High-Level Topology

**Option A: Peer-to-Peer (Decentralized)**
```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│ FastGate A  │◄─────►│ FastGate B  │◄─────►│ FastGate C  │
│ (homelab1)  │ TAXII │ (homelab2)  │ TAXII │ (homelab3)  │
│             │       │             │       │             │
│ - Publishes │       │ - Subscribes│       │ - Aggregates│
│ - Consumes  │       │ - Filters   │       │ - Republishes│
└─────────────┘       └─────────────┘       └─────────────┘
```

**Option B: Hub-and-Spoke (Semi-Centralized)**
```
                ┌─────────────────────────────┐
                │  Community TAXII Hub        │
                │  (Trusted community member) │
                │  - Aggregates indicators    │
                │  - Deduplicates             │
                │  - Validates signatures     │
                └──────────┬──────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐       ┌─────▼────┐      ┌─────▼────┐
   │FastGate │       │ FastGate │      │ FastGate │
   │ Instance│       │ Instance │      │ Instance │
   │    A    │       │    B     │      │    C     │
   └─────────┘       └──────────┘      └──────────┘

   Publish: Local attacks → Hub → Broadcast to peers
   Consume: Hub → Local blocklist
```

### 2.2 STIX/TAXII Overview

**STIX (Structured Threat Information eXpression):**
JSON-based format for threat indicators:
```json
{
  "type": "bundle",
  "id": "bundle--abc123",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--xyz789",
      "created": "2025-11-17T10:00:00Z",
      "modified": "2025-11-17T10:00:00Z",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "valid_from": "2025-11-17T10:00:00Z",
      "valid_until": "2025-11-17T11:00:00Z",
      "labels": ["malicious-activity", "ddos", "layer7"],
      "confidence": 85,
      "description": "IP observed conducting L7 DDoS attack",
      "external_references": [
        {
          "source_name": "fastgate-instance-a",
          "description": "Blocked after 1000 req/s burst"
        }
      ]
    }
  ]
}
```

**TAXII (Trusted Automated eXchange of Intelligence Information):**
RESTful API for sharing STIX bundles:
```
GET  /taxii2/collections/          # List available feeds
GET  /taxii2/collections/{id}/objects/  # Fetch indicators
POST /taxii2/collections/{id}/objects/  # Publish indicators
```

### 2.3 Component Architecture

```
┌───────────────────────────────────────────────────────────┐
│ Decision Service (Go)                                     │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ internal/intel/                                     │ │
│  │  - taxii_client.go   → Subscribe to peer feeds     │ │
│  │  - taxii_server.go   → Publish local indicators    │ │
│  │  - stix_parser.go    → Parse STIX bundles          │ │
│  │  - indicator_store.go → LRU cache (TTL-based)      │ │
│  │  - publisher.go      → Auto-publish attack events  │ │
│  └─────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────┐ │
│  │ internal/authz/handler.go (MODIFIED)               │ │
│  │  - Check IP against shared blocklist               │ │
│  │  - Publish new threats on block decision           │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

---

## 3. Implementation Phases

### Phase 2.1: STIX Indicator Store (Week 1, Days 1-2)

**Files to create:**
- `decision-service/internal/intel/indicator.go`
- `decision-service/internal/intel/store.go`

**Task 1: Define indicator types**
```go
// decision-service/internal/intel/indicator.go
package intel

import "time"

type IndicatorType string

const (
    IndicatorIPv4       IndicatorType = "ipv4-addr"
    IndicatorIPv6       IndicatorType = "ipv6-addr"
    IndicatorUserAgent  IndicatorType = "user-agent"
    IndicatorPattern    IndicatorType = "pattern"
)

type Indicator struct {
    ID          string        `json:"id"`
    Type        IndicatorType `json:"type"`
    Value       string        `json:"value"`
    Confidence  int           `json:"confidence"`  // 0-100
    ValidFrom   time.Time     `json:"valid_from"`
    ValidUntil  time.Time     `json:"valid_until"`
    Labels      []string      `json:"labels"`
    Source      string        `json:"source"`
    Description string        `json:"description"`
}

func (i *Indicator) IsExpired() bool {
    return time.Now().After(i.ValidUntil)
}

func (i *Indicator) IsActive() bool {
    now := time.Now()
    return now.After(i.ValidFrom) && now.Before(i.ValidUntil)
}
```

**Task 2: Build indicator store**
```go
// decision-service/internal/intel/store.go
package intel

import (
    "container/list"
    "sync"
    "time"
)

type Store struct {
    mu        sync.RWMutex
    byType    map[IndicatorType]map[string]*list.Element  // type -> value -> entry
    lru       *list.List
    cap       int
    gcTicker  *time.Ticker
}

type entry struct {
    indicator *Indicator
}

func NewStore(capacity int) *Store {
    if capacity <= 0 {
        capacity = 50000
    }

    s := &Store{
        byType:   make(map[IndicatorType]map[string]*list.Element),
        lru:      list.New(),
        cap:      capacity,
        gcTicker: time.NewTicker(5 * time.Minute),
    }

    // Background GC for expired indicators
    go s.gcLoop()

    return s
}

func (s *Store) Add(ind *Indicator) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Skip expired indicators
    if ind.IsExpired() {
        return
    }

    // Initialize type map if needed
    if s.byType[ind.Type] == nil {
        s.byType[ind.Type] = make(map[string]*list.Element)
    }

    // Check if already exists (update)
    if el, exists := s.byType[ind.Type][ind.Value]; exists {
        en := el.Value.(*entry)
        en.indicator = ind
        s.lru.MoveToFront(el)
        return
    }

    // Evict LRU if at capacity
    if s.lru.Len() >= s.cap {
        s.evictLRU()
    }

    // Add new
    en := &entry{indicator: ind}
    el := s.lru.PushFront(en)
    s.byType[ind.Type][ind.Value] = el
}

func (s *Store) Check(typ IndicatorType, value string) (*Indicator, bool) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    typeMap, ok := s.byType[typ]
    if !ok {
        return nil, false
    }

    el, ok := typeMap[value]
    if !ok {
        return nil, false
    }

    en := el.Value.(*entry)
    if en.indicator.IsExpired() {
        return nil, false
    }

    return en.indicator, true
}

func (s *Store) evictLRU() {
    back := s.lru.Back()
    if back == nil {
        return
    }

    en := back.Value.(*entry)
    ind := en.indicator

    delete(s.byType[ind.Type], ind.Value)
    s.lru.Remove(back)
}

func (s *Store) gcLoop() {
    for range s.gcTicker.C {
        s.gc()
    }
}

func (s *Store) gc() {
    s.mu.Lock()
    defer s.mu.Unlock()

    now := time.Now()
    for el := s.lru.Front(); el != nil; {
        next := el.Next()
        en := el.Value.(*entry)

        if now.After(en.indicator.ValidUntil) {
            delete(s.byType[en.indicator.Type], en.indicator.Value)
            s.lru.Remove(el)
        }

        el = next
    }
}

func (s *Store) Stats() map[string]int {
    s.mu.RLock()
    defer s.mu.RUnlock()

    stats := make(map[string]int)
    for typ, m := range s.byType {
        stats[string(typ)] = len(m)
    }
    stats["total"] = s.lru.Len()
    return stats
}
```

### Phase 2.2: STIX Parser (Week 1, Days 3-4)

**Files to create:**
- `decision-service/internal/intel/stix.go`

**Dependencies:**
```bash
go get github.com/TcM1911/stix2@latest
```

**Task: Parse STIX bundles**
```go
// decision-service/internal/intel/stix.go
package intel

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/TcM1911/stix2"
)

type STIXParser struct{}

func NewSTIXParser() *STIXParser {
    return &STIXParser{}
}

func (p *STIXParser) ParseBundle(data []byte) ([]*Indicator, error) {
    var bundle stix2.Bundle
    if err := json.Unmarshal(data, &bundle); err != nil {
        return nil, err
    }

    indicators := make([]*Indicator, 0, len(bundle.Objects))

    for _, obj := range bundle.Objects {
        if obj.GetType() != "indicator" {
            continue
        }

        stixInd, ok := obj.(*stix2.Indicator)
        if !ok {
            continue
        }

        ind := p.convertIndicator(stixInd)
        if ind != nil {
            indicators = append(indicators, ind)
        }
    }

    return indicators, nil
}

func (p *STIXParser) convertIndicator(stixInd *stix2.Indicator) *Indicator {
    // Parse pattern: "[ipv4-addr:value = '192.0.2.1']"
    typ, value, err := parseSTIXPattern(stixInd.Pattern)
    if err != nil {
        return nil
    }

    validFrom := stixInd.ValidFrom.Time()
    validUntil := validFrom.Add(24 * time.Hour) // Default 24h TTL

    if stixInd.ValidUntil != nil {
        validUntil = stixInd.ValidUntil.Time()
    }

    confidence := 50  // Default medium confidence
    if stixInd.Confidence != nil {
        confidence = *stixInd.Confidence
    }

    return &Indicator{
        ID:          stixInd.ID,
        Type:        typ,
        Value:       value,
        Confidence:  confidence,
        ValidFrom:   validFrom,
        ValidUntil:  validUntil,
        Labels:      stixInd.Labels,
        Description: stixInd.Description,
        Source:      extractSource(stixInd),
    }
}

func parseSTIXPattern(pattern string) (IndicatorType, string, error) {
    // Simple regex-based parser for common patterns
    // "[ipv4-addr:value = '192.0.2.1']" → (IndicatorIPv4, "192.0.2.1")

    // For MVP, support only IP addresses
    // Future: Use proper STIX pattern parser

    if len(pattern) < 10 {
        return "", "", fmt.Errorf("pattern too short")
    }

    // Extract type
    if contains(pattern, "ipv4-addr") {
        value := extractQuotedValue(pattern)
        return IndicatorIPv4, value, nil
    }

    if contains(pattern, "ipv6-addr") {
        value := extractQuotedValue(pattern)
        return IndicatorIPv6, value, nil
    }

    return "", "", fmt.Errorf("unsupported pattern type")
}

func extractQuotedValue(s string) string {
    // Extract value between single quotes
    start := -1
    for i, c := range s {
        if c == '\'' {
            if start == -1 {
                start = i + 1
            } else {
                return s[start:i]
            }
        }
    }
    return ""
}

func extractSource(ind *stix2.Indicator) string {
    if len(ind.ExternalReferences) > 0 {
        return ind.ExternalReferences[0].SourceName
    }
    return "unknown"
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && s[:len(substr)] == substr
}
```

### Phase 2.3: TAXII Client (Week 1, Days 5-7)

**Files to create:**
- `decision-service/internal/intel/taxii_client.go`

**Task: Subscribe to peer feeds**
```go
// decision-service/internal/intel/taxii_client.go
package intel

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

type TAXIIClient struct {
    BaseURL    string
    Username   string
    Password   string
    HTTPClient *http.Client
}

func NewTAXIIClient(baseURL, username, password string) *TAXIIClient {
    return &TAXIIClient{
        BaseURL:  baseURL,
        Username: username,
        Password: password,
        HTTPClient: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

func (c *TAXIIClient) FetchIndicators(collectionID string, addedAfter time.Time) ([]byte, error) {
    url := fmt.Sprintf("%s/taxii2/collections/%s/objects/", c.BaseURL, collectionID)

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    // Add authentication
    if c.Username != "" {
        req.SetBasicAuth(c.Username, c.Password)
    }

    // Add filters
    q := req.URL.Query()
    if !addedAfter.IsZero() {
        q.Set("added_after", addedAfter.Format(time.RFC3339))
    }
    req.URL.RawQuery = q.Encode()

    // Set headers
    req.Header.Set("Accept", "application/taxii+json;version=2.1")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("TAXII server returned %d", resp.StatusCode)
    }

    return io.ReadAll(resp.Body)
}

func (c *TAXIIClient) ListCollections() ([]Collection, error) {
    url := fmt.Sprintf("%s/taxii2/collections/", c.BaseURL)

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    if c.Username != "" {
        req.SetBasicAuth(c.Username, c.Password)
    }

    req.Header.Set("Accept", "application/taxii+json;version=2.1")

    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result struct {
        Collections []Collection `json:"collections"`
    }

    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    return result.Collections, nil
}

type Collection struct {
    ID          string `json:"id"`
    Title       string `json:"title"`
    Description string `json:"description"`
    CanRead     bool   `json:"can_read"`
    CanWrite    bool   `json:"can_write"`
}
```

**Task: Polling loop**
```go
// decision-service/internal/intel/poller.go
package intel

import (
    "log"
    "time"
)

type Poller struct {
    Client       *TAXIIClient
    Store        *Store
    Parser       *STIXParser
    CollectionID string
    Interval     time.Duration
    stopCh       chan struct{}
}

func NewPoller(client *TAXIIClient, store *Store, collectionID string, interval time.Duration) *Poller {
    return &Poller{
        Client:       client,
        Store:        store,
        Parser:       NewSTIXParser(),
        CollectionID: collectionID,
        Interval:     interval,
        stopCh:       make(chan struct{}),
    }
}

func (p *Poller) Start() {
    ticker := time.NewTicker(p.Interval)
    defer ticker.Stop()

    // Initial fetch
    p.poll()

    for {
        select {
        case <-ticker.C:
            p.poll()
        case <-p.stopCh:
            return
        }
    }
}

func (p *Poller) Stop() {
    close(p.stopCh)
}

func (p *Poller) poll() {
    // Fetch indicators added in last polling interval
    addedAfter := time.Now().Add(-p.Interval)

    data, err := p.Client.FetchIndicators(p.CollectionID, addedAfter)
    if err != nil {
        log.Printf("TAXII fetch error: %v", err)
        return
    }

    indicators, err := p.Parser.ParseBundle(data)
    if err != nil {
        log.Printf("STIX parse error: %v", err)
        return
    }

    // Add to store
    for _, ind := range indicators {
        p.Store.Add(ind)
    }

    if len(indicators) > 0 {
        log.Printf("Fetched %d indicators from TAXII feed", len(indicators))
    }
}
```

### Phase 2.4: TAXII Server (Week 2, Days 1-3)

**Files to create:**
- `decision-service/internal/intel/taxii_server.go`

**Task: Publish local indicators**
```go
// decision-service/internal/intel/taxii_server.go
package intel

import (
    "encoding/json"
    "net/http"
    "sync"
    "time"

    "github.com/TcM1911/stix2"
)

type TAXIIServer struct {
    mu          sync.RWMutex
    bundles     []*stix2.Bundle
    collections map[string]*Collection
}

func NewTAXIIServer() *TAXIIServer {
    return &TAXIIServer{
        bundles:     make([]*stix2.Bundle, 0, 1000),
        collections: make(map[string]*Collection),
    }
}

func (s *TAXIIServer) RegisterCollection(id, title, description string) {
    s.mu.Lock()
    defer s.mu.Unlock()

    s.collections[id] = &Collection{
        ID:          id,
        Title:       title,
        Description: description,
        CanRead:     true,
        CanWrite:    true,
    }
}

func (s *TAXIIServer) PublishIndicator(ind *Indicator) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Convert to STIX indicator
    stixInd := s.toSTIXIndicator(ind)

    // Create bundle
    bundle := &stix2.Bundle{
        Type: "bundle",
        ID:   stix2.Identifier(fmt.Sprintf("bundle--%s", randomID())),
        Objects: []stix2.STIXObject{
            stixInd,
        },
    }

    s.bundles = append(s.bundles, bundle)

    // Limit bundle history (keep last 1000)
    if len(s.bundles) > 1000 {
        s.bundles = s.bundles[len(s.bundles)-1000:]
    }

    return nil
}

func (s *TAXIIServer) HandleCollections(w http.ResponseWriter, r *http.Request) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    collections := make([]Collection, 0, len(s.collections))
    for _, c := range s.collections {
        collections = append(collections, *c)
    }

    resp := struct {
        Collections []Collection `json:"collections"`
    }{
        Collections: collections,
    }

    w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
    json.NewEncoder(w).Encode(resp)
}

func (s *TAXIIServer) HandleObjects(w http.ResponseWriter, r *http.Request) {
    collectionID := r.URL.Query().Get("collection_id")
    addedAfter := r.URL.Query().Get("added_after")

    s.mu.RLock()
    defer s.mu.RUnlock()

    var filteredBundles []*stix2.Bundle

    if addedAfter != "" {
        t, _ := time.Parse(time.RFC3339, addedAfter)
        for _, bundle := range s.bundles {
            // Filter bundles created after specified time
            // (In production, store creation time separately)
            filteredBundles = append(filteredBundles, bundle)
        }
    } else {
        filteredBundles = s.bundles
    }

    // Merge all bundles into one response
    mergedObjects := make([]stix2.STIXObject, 0)
    for _, bundle := range filteredBundles {
        mergedObjects = append(mergedObjects, bundle.Objects...)
    }

    responseBundle := &stix2.Bundle{
        Type:    "bundle",
        ID:      stix2.Identifier(fmt.Sprintf("bundle--%s", randomID())),
        Objects: mergedObjects,
    }

    w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
    json.NewEncoder(w).Encode(responseBundle)
}

func (s *TAXIIServer) toSTIXIndicator(ind *Indicator) *stix2.Indicator {
    pattern := fmt.Sprintf("[%s:value = '%s']", ind.Type, ind.Value)

    confidence := ind.Confidence

    stixInd := &stix2.Indicator{
        Type:        "indicator",
        ID:          stix2.Identifier(ind.ID),
        Pattern:     pattern,
        PatternType: "stix",
        ValidFrom:   &stix2.Timestamp{Time: ind.ValidFrom},
        ValidUntil:  &stix2.Timestamp{Time: ind.ValidUntil},
        Labels:      ind.Labels,
        Confidence:  &confidence,
        Description: ind.Description,
    }

    if ind.Source != "" {
        stixInd.ExternalReferences = []stix2.ExternalReference{
            {
                SourceName:  ind.Source,
                Description: fmt.Sprintf("Published by %s", ind.Source),
            },
        }
    }

    return stixInd
}

func randomID() string {
    return fmt.Sprintf("%d", time.Now().UnixNano())
}
```

### Phase 2.5: Integration with Authz (Week 2, Days 4-5)

**Files to modify:**
- `decision-service/internal/authz/handler.go`
- `decision-service/cmd/fastgate/main.go`

**Task 1: Check indicators in scoring**
```go
// decision-service/internal/authz/handler.go (add field)
type Handler struct {
    Cfg       *config.Config
    Keyring   *token.Keyring
    IPRPS     *rate.SlidingRPS
    TokenRPS  *rate.SlidingRPS
    WSConcIP  *rate.Concurrency
    WSConcTok *rate.Concurrency
    wsLease   time.Duration
    IntelStore *intel.Store  // NEW
}

// Modify computeScore
func (h *Handler) computeScore(r *http.Request, method, uri, clientIP string, wsUpgrade bool, hadInvalidToken bool) (int, []string) {
    score := 0
    reasons := make([]string, 0, 8)

    // NEW: Check threat intelligence
    if h.IntelStore != nil && clientIP != "" {
        if ind, found := h.IntelStore.Check(intel.IndicatorIPv4, clientIP); found {
            // Boost score based on confidence
            boost := ind.Confidence / 2  // 0-50 points
            score += boost
            reasons = append(reasons, fmt.Sprintf("threat_intel_ip(confidence=%d)", ind.Confidence))
        }
    }

    // ... rest of scoring logic
}
```

**Task 2: Publish attacks**
```go
// decision-service/internal/authz/handler.go (add to ServeHTTP)

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // ... existing logic ...

    // After block decision
    if score >= h.Cfg.Policy.BlockThreshold {
        metrics.AuthzDecision.WithLabelValues("block").Inc()

        // NEW: Publish to threat intel
        if h.IntelStore != nil && clientIP != "" {
            go h.publishThreat(clientIP, score, reasons)
        }

        setReasonHeaders(w, reasons, score)
        http.Error(w, "blocked", http.StatusForbidden)
        return
    }
}

func (h *Handler) publishThreat(ip string, score int, reasons []string) {
    ind := &intel.Indicator{
        ID:          fmt.Sprintf("indicator--%d", time.Now().UnixNano()),
        Type:        intel.IndicatorIPv4,
        Value:       ip,
        Confidence:  min(score, 100),
        ValidFrom:   time.Now(),
        ValidUntil:  time.Now().Add(1 * time.Hour),  // Short TTL for IP blocks
        Labels:      []string{"malicious-activity", "ddos", "layer7"},
        Source:      "fastgate",
        Description: fmt.Sprintf("Blocked with score %d: %s", score, strings.Join(reasons, ", ")),
    }

    // Publisher will handle TAXII distribution
    h.IntelStore.Add(ind)
}
```

**Task 3: Wire up in main.go**
```go
// decision-service/cmd/fastgate/main.go

var intelStore *intel.Store
var taxiiServer *intel.TAXIIServer

if cfg.ThreatIntel.Enabled {
    intelStore = intel.NewStore(cfg.ThreatIntel.CacheCapacity)

    // Start TAXII server (publish)
    taxiiServer = intel.NewTAXIIServer()
    taxiiServer.RegisterCollection("fastgate", "FastGate Indicators", "L7 attack indicators")

    mux.Handle("/taxii2/collections/", http.HandlerFunc(taxiiServer.HandleCollections))
    mux.Handle("/taxii2/collections/fastgate/objects/", http.HandlerFunc(taxiiServer.HandleObjects))

    // Start TAXII clients (subscribe to peers)
    for _, peer := range cfg.ThreatIntel.Peers {
        client := intel.NewTAXIIClient(peer.URL, peer.Username, peer.Password)
        poller := intel.NewPoller(client, intelStore, peer.CollectionID, 30*time.Second)
        go poller.Start()
    }

    log.Printf("Threat intel enabled (peers: %d, cache: %d)", len(cfg.ThreatIntel.Peers), cfg.ThreatIntel.CacheCapacity)
}

authzHandler := authz.NewHandler(cfg, kr)
authzHandler.IntelStore = intelStore  // Inject
```

---

## 4. Configuration

### 4.1 Config Schema
```yaml
# config.example.yaml
threat_intel:
  enabled: true
  cache_capacity: 50000  # Max indicators to store

  # Peers to subscribe to
  peers:
    - name: "friend1"
      url: "https://fastgate.friend1.com"
      collection_id: "fastgate"
      username: "fastgate-peer"
      password: "shared-secret"
      poll_interval_sec: 30

    - name: "friend2"
      url: "https://fastgate.friend2.com"
      collection_id: "fastgate"
      username: "fastgate-peer"
      password: "another-secret"
      poll_interval_sec: 30

  # Auto-publish local attacks
  auto_publish:
    enabled: true
    min_confidence: 70  # Only publish high-confidence blocks
    ttl_hours: 1        # How long indicators remain valid

  # External feeds (AlienVault OTX, MISP, etc.)
  external_feeds:
    - name: "AlienVault OTX"
      url: "https://otx.alienvault.com/taxii"
      collection_id: "public"
      poll_interval_sec: 300
```

### 4.2 Privacy Controls
```yaml
threat_intel:
  privacy:
    # Anonymize IPs before sharing
    anonymize_ips: true
    subnet_prefix_ipv4: 24  # Share /24 instead of /32
    subnet_prefix_ipv6: 64  # Share /64 instead of /128

    # Share only aggregated patterns
    share_raw_logs: false

    # Require signatures for all published indicators
    sign_indicators: true
    signing_key: "path/to/private.key"
```

---

## 5. Security Considerations

### 5.1 Sybil Attack Prevention
**Problem**: Attacker creates many fake FastGate instances to poison threat intel.

**Solution 1: Require domain verification**
```yaml
threat_intel:
  peers:
    - url: "https://fastgate.friend1.com"
      verify_domain: true  # Check TXT record
      dns_verification:
        record: "_fastgate-peer.friend1.com"
        expected: "fastgate-instance-id-abc123"
```

**Solution 2: Web of trust**
```yaml
threat_intel:
  trust_model: "web_of_trust"
  trusted_peers:
    - fingerprint: "sha256:abc123..."
      weight: 1.0
  untrusted_threshold: 0.3  # Ignore indicators with <30% trusted votes
```

### 5.2 Indicator Validation
```go
// Only accept indicators matching certain criteria
func (s *Store) Add(ind *Indicator) error {
    // Reject future-dated indicators
    if ind.ValidFrom.After(time.Now().Add(5 * time.Minute)) {
        return errors.New("future-dated indicator rejected")
    }

    // Reject very long TTLs (max 24h)
    if ind.ValidUntil.Sub(ind.ValidFrom) > 24*time.Hour {
        return errors.New("TTL too long")
    }

    // Reject private IPs
    if isPrivateIP(ind.Value) {
        return errors.New("private IP rejected")
    }

    s.add(ind)
    return nil
}
```

---

## 6. Testing Plan

### 6.1 Unit Tests
```go
// decision-service/internal/intel/store_test.go
func TestStore_AddAndCheck(t *testing.T) {
    store := NewStore(100)

    ind := &Indicator{
        ID:         "test-1",
        Type:       IndicatorIPv4,
        Value:      "203.0.113.42",
        Confidence: 80,
        ValidFrom:  time.Now(),
        ValidUntil: time.Now().Add(1 * time.Hour),
    }

    store.Add(ind)

    result, found := store.Check(IndicatorIPv4, "203.0.113.42")
    if !found {
        t.Fatal("Expected indicator to be found")
    }

    if result.Confidence != 80 {
        t.Errorf("Expected confidence 80, got %d", result.Confidence)
    }
}

func TestStore_ExpirationGC(t *testing.T) {
    store := NewStore(100)

    ind := &Indicator{
        ID:         "test-2",
        Type:       IndicatorIPv4,
        Value:      "203.0.113.43",
        ValidUntil: time.Now().Add(-1 * time.Hour),  // Expired
    }

    store.Add(ind)

    _, found := store.Check(IndicatorIPv4, "203.0.113.43")
    if found {
        t.Error("Expired indicator should not be returned")
    }
}
```

### 6.2 Integration Tests
```bash
# Test TAXII federation between two instances
docker compose -f test/taxii-federation.yaml up

# Instance A blocks IP → publishes indicator
curl -H "X-Forwarded-For: 203.0.113.42" http://instanceA:8088/login

# Instance B polls instance A → receives indicator
sleep 35  # Wait for polling interval

# Instance B should now block same IP
curl -H "X-Forwarded-For: 203.0.113.42" http://instanceB:8088/login
# Expected: 403 Forbidden (threat_intel_ip reason)
```

---

## 7. Deployment Examples

### 7.1 Docker Compose (3 Peers)
```yaml
# test/taxii-federation.yaml
version: '3.8'

services:
  fastgate-a:
    build: ../deploy/decision.Dockerfile
    environment:
      - FASTGATE_CONFIG=/etc/fastgate/config-a.yaml
    volumes:
      - ./config-a.yaml:/etc/fastgate/config-a.yaml
    ports:
      - "8080:8080"

  fastgate-b:
    build: ../deploy/decision.Dockerfile
    environment:
      - FASTGATE_CONFIG=/etc/fastgate/config-b.yaml
    volumes:
      - ./config-b.yaml:/etc/fastgate/config-b.yaml
    ports:
      - "8081:8080"

  fastgate-c:
    build: ../deploy/decision.Dockerfile
    environment:
      - FASTGATE_CONFIG=/etc/fastgate/config-c.yaml
    volumes:
      - ./config-c.yaml:/etc/fastgate/config-c.yaml
    ports:
      - "8082:8080"

# Each config.yaml points to the other two as peers
```

### 7.2 External Feed Integration
```yaml
# Subscribe to AlienVault OTX
threat_intel:
  enabled: true
  external_feeds:
    - name: "AlienVault OTX"
      url: "https://otx.alienvault.com/taxii"
      collection_id: "41"  # Malicious IPs collection
      poll_interval_sec: 600
```

---

## 8. Metrics & Observability

```go
// decision-service/internal/metrics/metrics.go
var (
    IntelIndicatorsTotal = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "fastgate_intel_indicators_total",
            Help: "Total indicators in store by type",
        },
        []string{"type"},
    )

    IntelBlocksTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "fastgate_intel_blocks_total",
            Help: "Requests blocked due to threat intel",
        },
        []string{"source"},
    )

    TAXIIPollsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "fastgate_taxii_polls_total",
            Help: "TAXII feed polls",
        },
        []string{"peer", "result"},
    )
)
```

---

## 9. Success Definition

**Innovation Score: 8/10**
- First decentralized threat sharing for L7 gateways
- Privacy-preserving (no centralized vendor)
- Compatible with existing STIX/TAXII ecosystem
- Enables collective homelab defense

**Effort vs Impact:**
- Effort: 1-2 weeks (low)
- Impact: Medium-High (community value)
- Differentiation: Unique federation model

**Next Steps:**
After Phase 2 completion, proceed to:
- Phase 3: Behavioral Entropy Fingerprinting
- Phase 4: Edge-Distributed Challenge Mesh
