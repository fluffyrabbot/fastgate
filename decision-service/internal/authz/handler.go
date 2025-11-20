package authz

import (
	"fmt"
	"hash"
	"hash/fnv"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/httputil"
	"fastgate/decision-service/internal/intel"
	"fastgate/decision-service/internal/metrics"
	"fastgate/decision-service/internal/rate"
	"fastgate/decision-service/internal/token"
)

// Pool for hash.Hash64 to reduce allocations in WebSocket path
var hashPool = sync.Pool{
	New: func() interface{} { return fnv.New64a() },
}

type Handler struct {
	Cfg         *config.Config
	Keyring     *token.Keyring
	IPRPS       *rate.SlidingRPS
	TokenRPS    *rate.SlidingRPS
	WSConcIP    *rate.Concurrency
	WSConcTok   *rate.Concurrency
	IntelStore  *intel.Store
	TAXIIServer *intel.TAXIIServer
}

func NewHandler(cfg *config.Config, kr *token.Keyring) *Handler {
	return &Handler{
		Cfg:       cfg,
		Keyring:   kr,
		IPRPS:     rate.NewSlidingRPS(10), // ~10s sliding window
		TokenRPS:  rate.NewSlidingRPS(10),
		WSConcIP:  rate.NewConcurrency(50000), // bounded maps
		WSConcTok: rate.NewConcurrency(50000),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		metrics.AuthzDuration.Observe(time.Since(start).Seconds())
	}()

	// Short-circuit in Observe mode: allow and opportunistically set cookie.
	if !h.Cfg.Modes.Enforce {
		if tokenStr, err := h.Keyring.Sign("low", h.Cfg.CookieMaxAge()); err == nil {
			http.SetCookie(w, httputil.BuildCookie(h.Cfg, tokenStr))
			metrics.ClearanceIssued.Inc()
		}
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Parse headers once to avoid repeated lookups
	method := r.Header.Get("X-Original-Method")
	if method == "" {
		method = r.Method
	}
	uri := r.Header.Get("X-Original-URI")
	if uri == "" {
		uri = r.URL.RequestURI()
	}
	clientIP := r.Header.Get("X-Client-IP")
	wsUpgrade := strings.EqualFold(r.Header.Get("X-WS-Upgrade"), "websocket")
	ua := r.Header.Get("User-Agent")
	hasLang := r.Header.Get("Accept-Language") != ""

	// Try existing clearance.
	var rawTok string
	if c, err := r.Cookie(h.Cfg.Cookie.Name); err == nil {
		rawTok = c.Value
	}

	// Validate token with small safety window (minLeft) so we don't let a near-expiry token start a WS.
	var tokValid bool
	if rawTok != "" {
		if _, ok, _ := h.Keyring.Verify(rawTok, 2*time.Minute); ok {
			tokValid = true
		} else {
			metrics.InvalidTokens.Inc()
		}
	}

	// If we already have a valid token and it's a WS upgrade, enforce concurrency caps first.
	// Only if caps pass do we ALLOW immediately.
	if tokValid && wsUpgrade {
		ok, ipAcq, tokAcq, reason := h.tryAcquireWS(clientIP, rawTok)
		if !ok {
			// Release anything we might have acquired (defensive).
			if ipAcq {
				h.WSConcIP.Release(h.wsIPKey(clientIP))
			}
			if tokAcq {
				h.WSConcTok.Release(h.wsTokKey(rawTok))
			}
			metrics.AuthzDecision.WithLabelValues("challenge").Inc()
			metrics.WSUpgrades.WithLabelValues("deny").Inc()
			setReasonHeaders(w, []string{reason}, 0)
			http.Error(w, "challenge", http.StatusUnauthorized)
			return
		}
		// Caps passed; allow and defer release to proxy lifecycle.
		metrics.WSUpgrades.WithLabelValues("allow").Inc()
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		// No need to reissue cookie; it's already valid, but refreshing is OK to reduce future near-expiry.
		if tokenStr, err := h.Keyring.Sign("low", h.Cfg.CookieMaxAge()); err == nil {
			http.SetCookie(w, httputil.BuildCookie(h.Cfg, tokenStr))
			metrics.ClearanceIssued.Inc()
		}
		// Defer lease release until proxy completes upgrade and connection closes.
		h.setWSLeaseHeader(w, ipAcq, clientIP, tokAcq, rawTok)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Valid token and not a WS ⇒ allow immediately.
	if tokValid && !wsUpgrade {
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Otherwise, compute risk & decide (covers non-token flows and invalid/near-expiry tokens).
	// Compute score with pre-parsed headers
	score, reasons := h.computeScore(method, uri, clientIP, wsUpgrade, rawTok != "" && !tokValid, ua, hasLang)

	if h.Cfg.Modes.UnderAttack {
		score += 15
		reasons = append(reasons, "under_attack")
	}

	// Decision tree (block/challenge/allow)
	if score >= h.Cfg.Policy.BlockThreshold {
		metrics.AuthzDecision.WithLabelValues("block").Inc()
		if wsUpgrade {
			metrics.WSUpgrades.WithLabelValues("deny").Inc()
		}

		// Security event logging with full context
		logger := httputil.GetLogger(r.Context())
		logger.Warn().
			Str("decision", "block").
			Str("request_id", httputil.GetRequestID(r.Context())).
			Str("client_ip", clientIP).
			Str("user_agent", ua).
			Int("score", score).
			Interface("reasons", reasons).
			Str("method", method).
			Str("uri", uri).
			Msg("authz decision: blocked")

		// Auto-publish to threat intel
		if h.IntelStore != nil && h.TAXIIServer != nil && clientIP != "" {
			go h.publishThreat(clientIP, score, reasons)
		}

		setReasonHeaders(w, reasons, score)
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	if score >= h.Cfg.Policy.ChallengeThreshold {
		metrics.AuthzDecision.WithLabelValues("challenge").Inc()
		if wsUpgrade {
			metrics.WSUpgrades.WithLabelValues("deny").Inc()
		}

		// Security event logging with full context
		if h.Cfg.Logging.Level == "debug" {
			logger := httputil.GetLogger(r.Context())
			logger.Debug().
				Str("decision", "challenge").
				Str("request_id", httputil.GetRequestID(r.Context())).
				Str("client_ip", clientIP).
				Str("user_agent", ua).
				Int("score", score).
				Interface("reasons", reasons).
				Str("method", method).
				Str("uri", uri).
				Msg("authz decision: challenge")
		}

		setReasonHeaders(w, reasons, score)
		http.Error(w, "challenge", http.StatusUnauthorized)
		return
	}

	// ALLOW path: issue clearance; for WS, enforce per-IP (no-token) concurrency caps.
	tokenStr, err := h.Keyring.Sign("low", h.Cfg.CookieMaxAge())
	if err == nil {
		http.SetCookie(w, httputil.BuildCookie(h.Cfg, tokenStr))
		metrics.ClearanceIssued.Inc()
	}
	if wsUpgrade {
		ok, ipAcq, _, reason := h.tryAcquireWS(clientIP, "") // no per-token cap without a valid token
		if !ok {
			if ipAcq {
				h.WSConcIP.Release(h.wsIPKey(clientIP))
			}
			metrics.AuthzDecision.WithLabelValues("challenge").Inc()
			metrics.WSUpgrades.WithLabelValues("deny").Inc()
			setReasonHeaders(w, append(reasons, reason), score)
			http.Error(w, "challenge", http.StatusUnauthorized)
			return
		}
		metrics.WSUpgrades.WithLabelValues("allow").Inc()
		h.setWSLeaseHeader(w, ipAcq, clientIP, false, "") // release IP lease after proxy finishes
	}
	metrics.AuthzDecision.WithLabelValues("allow").Inc()

	// Debug logging
	if h.Cfg.Logging.Level == "debug" {
		logger := httputil.GetLogger(r.Context())
		logger.Debug().
			Str("decision", "allow").
			Str("request_id", httputil.GetRequestID(r.Context())).
			Str("client_ip", clientIP).
			Str("user_agent", ua).
			Int("score", score).
			Interface("reasons", reasons).
			Str("method", method).
			Str("uri", uri).
			Msg("authz decision: allow")
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---- Scoring (unchanged except for reason details) ----

func (h *Handler) computeScore(method, uri, clientIP string, wsUpgrade bool, hadInvalidToken bool, ua string, hasLang bool) (int, []string) {
	score := 0
	reasons := make([]string, 0, 8)

	// Check threat intelligence
	if h.IntelStore != nil && clientIP != "" {
		if ind, found := h.IntelStore.Check(intel.IndicatorIPv4, clientIP); found {
			// Boost score based on confidence
			boost := ind.Confidence / 2 // 0-50 points
			score += boost
			// Optimize: use simple reason code, confidence is logged separately via metrics
			reasons = append(reasons, "threat_intel_ip")
			metrics.ThreatIntelMatches.WithLabelValues(string(ind.Type), ind.Source).Inc()
		}
	}

	// Path base risk (first match)
	for _, pr := range h.Cfg.Policy.Paths {
		if pr.Base > 0 && pr.Re.MatchString(uri) {
			score += pr.Base
			reasons = append(reasons, "path_base")
			break
		}
	}
	// Mutating methods
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		score += 15
		reasons = append(reasons, "mutating_method")
	}
	// WS hint
	if wsUpgrade {
		score += 10
		reasons = append(reasons, "ws_upgrade")
	}
	// UA & language (use pre-lowercased UA for efficiency)
	uaLower := strings.ToLower(ua)
	if ua == "" {
		score += 15
		reasons = append(reasons, "ua_missing")
	} else if looksHeadless(uaLower) {
		score += 15
		reasons = append(reasons, "ua_headless")
	}
	if !hasLang {
		score += 10
		reasons = append(reasons, "al_missing")
	}
	// Invalid/expired token presented
	if hadInvalidToken {
		score += 10
		reasons = append(reasons, "clearance_invalid")
	}
	// IP RPS
	if clientIP != "" && h.Cfg.Policy.IPRPSThreshold > 0 {
		rps := h.IPRPS.Add("ip:" + clientIP)
		if rps > float64(h.Cfg.Policy.IPRPSThreshold) {
			over := int(2 * (rps - float64(h.Cfg.Policy.IPRPSThreshold)))
			if over > 30 {
				over = 30
			}
			if over > 0 {
				score += over
				reasons = append(reasons, "ip_rps")
			}
		}
	}
	// Token RPS bucket for invalids (coarse)
	if hadInvalidToken && h.Cfg.Policy.TokenRPSThreshold > 0 {
		rps := h.TokenRPS.Add("tok:invalid")
		if rps > float64(h.Cfg.Policy.TokenRPSThreshold) {
			over := int(2 * (rps - float64(h.Cfg.Policy.TokenRPSThreshold)))
			if over > 30 {
				over = 30
			}
			if over > 0 {
				score += over
				reasons = append(reasons, "tok_rps")
			}
		}
	}

	return score, reasons
}

func looksHeadless(ua string) bool {
	switch {
	case strings.Contains(ua, "curl"),
		strings.Contains(ua, "python-requests"),
		strings.Contains(ua, "go-http-client"),
		strings.Contains(ua, "wget"),
		strings.Contains(ua, "java"):
		return true
	default:
		return false
	}
}

// ---- WS concurrency helpers ----

// WSLeaseHeader carries internal lease metadata between authz and proxy handlers.
const WSLeaseHeader = "X-FastGate-WS-Lease"

// WSLease represents resources reserved for a WebSocket connection.
type WSLease struct {
	IPKey    string
	TokenKey string
}

func (l WSLease) headerValue() string {
	parts := make([]string, 0, 2)
	if l.IPKey != "" {
		parts = append(parts, "ip="+l.IPKey)
	}
	if l.TokenKey != "" {
		parts = append(parts, "tok="+l.TokenKey)
	}
	return strings.Join(parts, ",")
}

// ParseWSLeaseHeader parses a serialized lease header into a WSLease.
func ParseWSLeaseHeader(val string) *WSLease {
	if val == "" {
		return nil
	}
	lease := &WSLease{}
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "ip":
			lease.IPKey = kv[1]
		case "tok":
			lease.TokenKey = kv[1]
		}
	}
	if lease.IPKey == "" && lease.TokenKey == "" {
		return nil
	}
	return lease
}

func (h *Handler) tryAcquireWS(clientIP, rawTok string) (ok bool, ipAcq bool, tokAcq bool, reason string) {
	// Per-IP cap
	if limit := h.Cfg.Policy.WSConcurrency.PerIP; limit > 0 && clientIP != "" {
		ipKey := h.wsIPKey(clientIP)
		if acquired, cur := h.WSConcIP.Acquire(ipKey, limit); !acquired {
			return false, false, false, "ws_concurrency_ip"
		} else {
			_ = cur
			ipAcq = true
		}
	}
	// Per-token cap (only if we have a valid token)
	if rawTok != "" {
		if limit := h.Cfg.Policy.WSConcurrency.PerToken; limit > 0 {
			tokKey := h.wsTokKey(rawTok)
			if acquired, cur := h.WSConcTok.Acquire(tokKey, limit); !acquired {
				// release IP if we took it
				if ipAcq {
					h.WSConcIP.Release(h.wsIPKey(clientIP))
				}
				return false, ipAcq, false, "ws_concurrency_token"
			} else {
				_ = cur
				tokAcq = true
			}
		}
	}
	return true, ipAcq, tokAcq, ""
}

func (h *Handler) setWSLeaseHeader(w http.ResponseWriter, ipAcq bool, clientIP string, tokAcq bool, rawTok string) {
	lease := WSLease{}
	if ipAcq && clientIP != "" {
		lease.IPKey = h.wsIPKey(clientIP)
	}
	if tokAcq && rawTok != "" {
		lease.TokenKey = h.wsTokKey(rawTok)
	}
	if lease.IPKey == "" && lease.TokenKey == "" {
		return
	}
	w.Header().Set(WSLeaseHeader, lease.headerValue())
}

// ReleaseWSLease releases any acquired WebSocket concurrency slots.
func (h *Handler) ReleaseWSLease(lease *WSLease) {
	if lease == nil {
		return
	}
	if lease.IPKey != "" {
		h.WSConcIP.Release(lease.IPKey)
	}
	if lease.TokenKey != "" {
		h.WSConcTok.Release(lease.TokenKey)
	}
}

// Shutdown gracefully shuts down the authz handler.
// WebSocket leases are now released by the proxy when connections close, so no timer cleanup is required.
func (h *Handler) Shutdown() {}

func (h *Handler) wsIPKey(ip string) string { return "ip:" + ip }
func (h *Handler) wsTokKey(tok string) string {
	return wsTokKey(tok)
}

// WSTokenKeyForTest exposes the internal token key derivation for tests.
func WSTokenKeyForTest(rawTok string) string {
	return wsTokKey(rawTok)
}

func wsTokKey(tok string) string {
	// Use a short, deterministic hash instead of the full JWT as the map key.
	// Pool hash objects to reduce allocations
	h64 := hashPool.Get().(hash.Hash64)
	defer hashPool.Put(h64)
	h64.Reset()

	_, _ = h64.Write([]byte(tok))
	sum := h64.Sum64()

	// compact hex without fmt to avoid allocs
	const hexdigits = "0123456789abcdef"
	var buf [20]byte // "tok:" + 16 hex chars
	copy(buf[:], "tok:")
	for i := 0; i < 16; i += 2 {
		shift := uint((7 - i/2) * 8)
		b := byte(sum >> shift)
		buf[4+i] = hexdigits[b>>4]
		buf[4+i+1] = hexdigits[b&0x0f]
	}
	return string(buf[:])
}

// ---- Response/headers & cookie helpers ----

func setReasonHeaders(w http.ResponseWriter, reasons []string, score int) {
	if len(reasons) == 0 {
		w.Header().Set("X-FastGate-Reason", "unspecified")
	} else {
		w.Header().Set("X-FastGate-Reason", strings.Join(reasons, ","))
	}
	w.Header().Set("X-FastGate-Score", strconv.Itoa(score))
}

// publishThreat publishes a blocked IP to the threat intelligence feed
func (h *Handler) publishThreat(ip string, score int, reasons []string) {
	// Panic recovery for goroutine safety
	defer func() {
		if r := recover(); r != nil {
			// Log panic but don't crash the service
			fmt.Fprintf(os.Stderr, "PANIC in publishThreat: %v\n", r)
		}
	}()

	ind := &intel.Indicator{
		ID:          fmt.Sprintf("indicator--%d", time.Now().UnixNano()),
		Type:        intel.IndicatorIPv4,
		Value:       ip,
		Confidence:  min(score, 100),
		ValidFrom:   time.Now(),
		ValidUntil:  time.Now().Add(1 * time.Hour), // Short TTL for IP blocks
		Labels:      []string{"malicious-activity", "ddos", "layer7"},
		Source:      "fastgate",
		Description: fmt.Sprintf("Blocked with score %d: %s", score, strings.Join(reasons, ", ")),
	}

	// Add to local store
	h.IntelStore.Add(ind)

	// Publish to TAXII server for peers to consume
	if err := h.TAXIIServer.PublishIndicator(ind); err != nil {
		// Log but don't fail the request
		_ = err
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
