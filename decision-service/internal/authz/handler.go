package authz

import (
	"hash/fnv"
	"net/http"
	"strings"
	"time"

	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/metrics"
	"fastgate/decision-service/internal/rate"
	"fastgate/decision-service/internal/token"
)

type Handler struct {
	Cfg       *config.Config
	Keyring   *token.Keyring
	IPRPS     *rate.SlidingRPS
	TokenRPS  *rate.SlidingRPS
	WSConcIP  *rate.Concurrency
	WSConcTok *rate.Concurrency
	wsLease   time.Duration // assumed WS lifetime; controls auto-release
}

func NewHandler(cfg *config.Config, kr *token.Keyring) *Handler {
	return &Handler{
		Cfg:       cfg,
		Keyring:   kr,
		IPRPS:     rate.NewSlidingRPS(10),        // ~10s sliding window
		TokenRPS:  rate.NewSlidingRPS(10),
		WSConcIP:  rate.NewConcurrency(50000),    // bounded maps
		WSConcTok: rate.NewConcurrency(50000),
		wsLease:   120 * time.Second,             // conservative default
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
			http.SetCookie(w, buildCookie(h.Cfg, tokenStr))
			metrics.ClearanceIssued.Inc()
		}
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		w.WriteHeader(http.StatusNoContent)
		return
	}

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
		// Caps passed; allow, set metrics, and schedule auto-release.
		metrics.WSUpgrades.WithLabelValues("allow").Inc()
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		// No need to reissue cookie; it's already valid, but refreshing is OK to reduce future near-expiry.
		if tokenStr, err := h.Keyring.Sign("low", h.Cfg.CookieMaxAge()); err == nil {
			http.SetCookie(w, buildCookie(h.Cfg, tokenStr))
			metrics.ClearanceIssued.Inc()
		}
		// Auto-release leases.
		h.deferWSRelease(clientIP, rawTok)
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
	score, reasons := h.computeScore(r, method, uri, clientIP, wsUpgrade, rawTok != "" && !tokValid)

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
		setReasonHeaders(w, reasons, score)
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}

	if score >= h.Cfg.Policy.ChallengeThreshold {
		metrics.AuthzDecision.WithLabelValues("challenge").Inc()
		if wsUpgrade {
			metrics.WSUpgrades.WithLabelValues("deny").Inc()
		}
		setReasonHeaders(w, reasons, score)
		http.Error(w, "challenge", http.StatusUnauthorized)
		return
	}

	// ALLOW path: issue clearance; for WS, enforce per-IP (no-token) concurrency caps.
	tokenStr, err := h.Keyring.Sign("low", h.Cfg.CookieMaxAge())
	if err == nil {
		http.SetCookie(w, buildCookie(h.Cfg, tokenStr))
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
		h.deferWSRelease(clientIP, "") // release IP lease
	}
	metrics.AuthzDecision.WithLabelValues("allow").Inc()
	w.WriteHeader(http.StatusNoContent)
}

// ---- Scoring (unchanged except for reason details) ----

func (h *Handler) computeScore(r *http.Request, method, uri, clientIP string, wsUpgrade bool, hadInvalidToken bool) (int, []string) {
	score := 0
	reasons := make([]string, 0, 8)

	// Path base risk (first match)
	for _, pr := range h.Cfg.Policy.Paths {
		if pr.Base > 0 && pr.re.MatchString(uri) {
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
	// UA & language
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	if ua == "" {
		score += 15
		reasons = append(reasons, "ua_missing")
	} else if looksHeadless(ua) {
		score += 15
		reasons = append(reasons, "ua_headless")
	}
	if r.Header.Get("Accept-Language") == "" {
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

func (h *Handler) deferWSRelease(clientIP, rawTok string) {
	// Auto-release after lease duration; best-effort cleanup.
	if limit := h.Cfg.Policy.WSConcurrency.PerIP; limit > 0 && clientIP != "" {
		ipKey := h.wsIPKey(clientIP)
		time.AfterFunc(h.wsLease, func() { h.WSConcIP.Release(ipKey) })
	}
	if rawTok != "" {
		if limit := h.Cfg.Policy.WSConcurrency.PerToken; limit > 0 {
			tokKey := h.wsTokKey(rawTok)
			time.AfterFunc(h.wsLease, func() { h.WSConcTok.Release(tokKey) })
		}
	}
}

func (h *Handler) wsIPKey(ip string) string  { return "ip:" + ip }
func (h *Handler) wsTokKey(tok string) string {
	// Use a short, deterministic hash instead of the full JWT as the map key.
	h64 := fnv.New64a()
	_, _ = h64.Write([]byte(tok))
	sum := h64.Sum64()
	// compact hex without fmt to avoid allocs
	const hexdigits = "0123456789abcdef"
	var buf [16]byte
	for i := 0; i < 16; i += 2 {
		shift := uint((7 - i/2) * 8)
		b := byte(sum >> shift)
		buf[i] = hexdigits[b>>4]
		buf[i+1] = hexdigits[b&0x0f]
	}
	return "tok:" + string(buf[:])
}

// ---- Response/headers & cookie helpers ----

func setReasonHeaders(w http.ResponseWriter, reasons []string, score int) {
	if len(reasons) == 0 {
		w.Header().Set("X-FastGate-Reason", "unspecified")
	} else {
		w.Header().Set("X-FastGate-Reason", strings.Join(reasons, ","))
	}
	w.Header().Set("X-FastGate-Score", itoa(score))
}

// Minimal int->string without fmt to avoid allocs on hot path
func itoa(i int) string {
	var b [12]byte
	pos := len(b)
	neg := i < 0
	u := uint32(i)
	if neg {
		u = uint32(-i)
	}
	if u == 0 {
		return "0"
	}
	for u > 0 {
		pos--
		b[pos] = byte('0' + (u % 10))
		u /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func buildCookie(cfg *config.Config, val string) *http.Cookie {
	c := &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    val,
		Path:     cfg.Cookie.Path,
		MaxAge:   cfg.Cookie.MaxAgeSec,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: cfg.Cookie.HTTPOnly,
	}
	switch strings.ToLower(cfg.Cookie.SameSite) {
	case "none":
		c.SameSite = http.SameSiteNoneMode
	default:
		c.SameSite = http.SameSiteLaxMode
	}
	if cfg.Cookie.Domain != "" {
		c.Domain = cfg.Cookie.Domain
	}
	return c
}
