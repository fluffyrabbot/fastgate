package proxy

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"fastgate/decision-service/internal/authz"
	"fastgate/decision-service/internal/config"
	internalhttp "fastgate/decision-service/internal/httputil"
	"fastgate/decision-service/internal/metrics"

	"github.com/rs/zerolog/log"
)

const (
	maxProxyCacheSize = 100                 // Maximum number of cached reverse proxies
	maxProxyBodySize  = 100 * 1024 * 1024   // 100MB max for proxied request bodies
	proxyCacheTTL     = 5 * time.Minute     // TTL for cached proxies (DNS change handling)
)

var (
	sanitizeReturnURL = internalhttp.SanitizeReturnURL
)

// cachedProxy wraps a reverse proxy with metadata
type cachedProxy struct {
	proxy      *httputil.ReverseProxy
	createdAt  time.Time
	originURL  string         // Store origin for LRU eviction
	lruElement *list.Element  // Pointer to element in LRU list
}

// Handler is an integrated reverse proxy that performs authorization checks inline
type Handler struct {
	cfg              *config.Config
	authzHandler     *authz.Handler
	proxies          map[string]*cachedProxy
	proxiesLRU       *list.List  // LRU list for cache eviction
	proxiesMu        sync.RWMutex
	challengePageDir string
}

// NewHandler creates a new integrated proxy handler
func NewHandler(cfg *config.Config, authzHandler *authz.Handler, challengePageDir string) (*Handler, error) {
	if !cfg.Proxy.Enabled {
		return nil, fmt.Errorf("proxy mode not enabled in config")
	}

	// Validate challenge page directory exists
	if _, err := os.Stat(challengePageDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("challenge page directory does not exist: %s", challengePageDir)
	}

	h := &Handler{
		cfg:              cfg,
		authzHandler:     authzHandler,
		proxies:          make(map[string]*cachedProxy),
		proxiesLRU:       list.New(),
		challengePageDir: challengePageDir,
	}

	return h, nil
}

// ServeHTTP handles incoming requests with integrated authorization and proxying
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Handle challenge page requests
	if h.isChallengePage(r.URL.Path) {
		h.serveChallengePage(w, r)
		return
	}

	// 2. Match route to get origin
	origin := h.matchRoute(r)
	if origin == "" {
		http.Error(w, "no route matched", http.StatusNotFound)
		return
	}

	// 3. Run authorization check inline
	decision, statusCode, cookies := h.checkAuthorization(r)

	// 4. Propagate any cookies from authz (clearance cookies)
	for _, cookie := range cookies {
		http.SetCookie(w, cookie)
	}

	// 5. Handle decision
	switch decision {
	case "block":
		metrics.AuthzDecision.WithLabelValues("block").Inc()
		http.Error(w, "blocked", statusCode)
		return

	case "challenge":
		metrics.AuthzDecision.WithLabelValues("challenge").Inc()
		// Redirect to challenge page with return URL (path + query only, no host)
		returnURL := r.URL.RequestURI()
		// Sanitize to prevent open redirects (uses existing httputil helper)
		returnURL = sanitizeReturnURL(returnURL)
		challengeURL := fmt.Sprintf("%s?return_url=%s", h.cfg.Proxy.ChallengePath, url.QueryEscape(returnURL))
		http.Redirect(w, r, challengeURL, http.StatusFound)
		return

	case "allow":
		metrics.AuthzDecision.WithLabelValues("allow").Inc()
		// Proxy to origin
		h.proxyToOrigin(w, r, origin)
		return

	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
}

// isChallengePage checks if the request path is for the challenge page
func (h *Handler) isChallengePage(path string) bool {
	challengePath := h.cfg.Proxy.ChallengePath
	return path == challengePath ||
		   path == challengePath+"/" ||
		   strings.HasPrefix(path, challengePath+"/")
}

// matchRoute finds the appropriate origin for the request
func (h *Handler) matchRoute(r *http.Request) string {
	// Simple single-origin mode
	if h.cfg.Proxy.Origin != "" {
		return h.cfg.Proxy.Origin
	}

	// Multi-origin routing
	host := r.Host
	path := r.URL.Path

	// Try to match routes in order
	for _, route := range h.cfg.Proxy.Routes {
		// Host-based routing (exact match)
		if route.Host != "" {
			if host == route.Host {
				return route.Origin
			}
		}

		// Path-based routing (regex match)
		if route.PathRe != nil {
			if route.PathRe.MatchString(path) {
				return route.Origin
			}
		}
	}

	// No match found
	return ""
}

// checkAuthorization runs the authorization logic and returns the decision and any cookies
func (h *Handler) checkAuthorization(r *http.Request) (decision string, statusCode int, cookies []*http.Cookie) {
	// Create a response recorder to capture authz handler output
	recorder := &authzRecorder{
		header:     make(http.Header),
		statusCode: http.StatusOK, // Default to 200 OK
	}

	// Prepare headers for authz handler (mimic NGINX auth_request format)
	r.Header.Set("X-Original-Method", r.Method)
	r.Header.Set("X-Original-URI", r.URL.RequestURI())

	// Get client IP from various headers
	clientIP := getClientIP(r)
	if clientIP != "" {
		r.Header.Set("X-Client-IP", clientIP)
	}

	// Check for WebSocket upgrade
	if isWebSocketUpgrade(r) {
		r.Header.Set("X-WS-Upgrade", "websocket")
	}

	// Call authz handler
	h.authzHandler.ServeHTTP(recorder, r)

	// If WriteHeader was never called, statusCode will be the default (200 OK)
	if recorder.statusCode == 0 {
		recorder.statusCode = http.StatusOK
	}

	// Extract cookies from authz response
	cookies = parseCookies(recorder.header)

	// Map status codes to decisions
	switch recorder.statusCode {
	case http.StatusOK, http.StatusNoContent: // 200/204 = ALLOW
		return "allow", http.StatusOK, cookies
	case http.StatusUnauthorized: // 401 = CHALLENGE
		return "challenge", http.StatusUnauthorized, cookies
	case http.StatusForbidden: // 403 = BLOCK
		return "block", http.StatusForbidden, cookies
	default:
		// Fail open or closed based on config
		if h.cfg.Modes.FailOpen {
			return "allow", http.StatusOK, cookies
		}
		return "block", http.StatusForbidden, cookies
	}
}

// proxyToOrigin forwards the request to the upstream origin
func (h *Handler) proxyToOrigin(w http.ResponseWriter, r *http.Request, originURL string) {
	// Get or create reverse proxy for this origin
	proxy := h.getOrCreateProxy(originURL)
	if proxy == nil {
		http.Error(w, "invalid origin", http.StatusInternalServerError)
		return
	}

	// Limit request body size to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, maxProxyBodySize)

	// Clean up auth-request headers before proxying
	r.Header.Del("X-Original-Method")
	r.Header.Del("X-Original-URI")
	r.Header.Del("X-Client-IP")
	r.Header.Del("X-WS-Upgrade")

	// Prevent request smuggling - detect suspicious header combinations
	if r.Header.Get("Content-Length") != "" && r.Header.Get("Transfer-Encoding") != "" {
		logger := internalhttp.GetLogger(r.Context())
		logger.Warn().
			Str("remote_addr", r.RemoteAddr).
			Msg("request smuggling attempt detected: both Content-Length and Transfer-Encoding present")
		// Per RFC 7230, Transfer-Encoding takes precedence
		r.Header.Del("Content-Length")
	}

	// Clear any existing X-Forwarded-* headers from untrusted clients
	// The proxy Director will set trusted values
	r.Header.Del("X-Forwarded-For")
	r.Header.Del("X-Forwarded-Proto")
	r.Header.Del("X-Forwarded-Host")

	// Proxy the request with latency tracking
	start := time.Now()
	proxy.ServeHTTP(w, r)
	duration := time.Since(start)

	// Record proxy latency metric
	metrics.ProxyLatency.WithLabelValues(originURL).Observe(duration.Seconds())
}

// getOrCreateProxy returns a reverse proxy for the given origin URL
func (h *Handler) getOrCreateProxy(originURL string) *httputil.ReverseProxy {
	// Check if we already have a proxy for this origin
	h.proxiesMu.Lock()
	if cp, ok := h.proxies[originURL]; ok {
		// Check if proxy is still fresh (TTL-based expiration for DNS updates)
		if time.Since(cp.createdAt) < proxyCacheTTL {
			// Move to front of LRU list (most recently used)
			h.proxiesLRU.MoveToFront(cp.lruElement)
			h.proxiesMu.Unlock()
			metrics.ProxyCacheOps.WithLabelValues("hit").Inc()
			return cp.proxy
		}
		// Expired, need to recreate
		if transport, ok := cp.proxy.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		h.proxiesLRU.Remove(cp.lruElement)
		delete(h.proxies, originURL)
		metrics.ProxyCacheOps.WithLabelValues("expiration").Inc()
	}
	h.proxiesMu.Unlock()

	// Cache miss - creating new proxy
	metrics.ProxyCacheOps.WithLabelValues("miss").Inc()

	// Create new proxy
	target, err := url.Parse(originURL)
	if err != nil {
		log.Error().Str("origin", originURL).Err(err).Msg("failed to parse origin URL")
		return nil
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Configure proxy transport with configurable timeouts and connection pools
	timeoutDuration := time.Duration(h.cfg.Proxy.TimeoutMs) * time.Millisecond
	proxy.Transport = &http.Transport{
		MaxIdleConns:          h.cfg.Proxy.MaxIdleConns,
		MaxIdleConnsPerHost:   h.cfg.Proxy.MaxIdleConnsPerHost,
		MaxConnsPerHost:       h.cfg.Proxy.MaxConnsPerHost,
		IdleConnTimeout:       time.Duration(h.cfg.Proxy.IdleTimeoutMs) * time.Millisecond,
		ResponseHeaderTimeout: timeoutDuration,
		TLSHandshakeTimeout:   timeoutDuration / 3, // 1/3 of total timeout for handshake
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableCompression: false,
		ForceAttemptHTTP2:  true,
	}

	// Configure director to set trusted X-Forwarded-* headers and propagate request ID
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Propagate request ID for distributed tracing
		if requestID := internalhttp.GetRequestID(req.Context()); requestID != "" {
			req.Header.Set("X-Request-ID", requestID)
		}

		// Set trusted X-Forwarded-* headers (untrusted ones were deleted earlier)
		if clientIP := getClientIP(req); clientIP != "" {
			// Append to preserve proxy chain if needed
			if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
				req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				req.Header.Set("X-Forwarded-For", clientIP)
			}
		}
		req.Header.Set("X-Forwarded-Proto", getScheme(req))
		req.Header.Set("X-Forwarded-Host", req.Host)
	}

	// Error handler with error differentiation and context handling
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger := internalhttp.GetLogger(r.Context())

		// Client disconnected - don't log as error
		if err == context.Canceled || err == context.DeadlineExceeded {
			logger.Debug().
				Str("origin", originURL).
				Str("error_type", "context").
				Msg("proxy request canceled")
			metrics.ProxyErrors.WithLabelValues(originURL, "context").Inc()
			return
		}

		// Differentiate timeout errors
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			logger.Warn().
				Str("origin", originURL).
				Str("error_type", "timeout").
				Err(err).
				Msg("proxy timeout")
			metrics.ProxyErrors.WithLabelValues(originURL, "timeout").Inc()
			http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
			return
		}

		// DNS errors
		if dnsErr, ok := err.(*net.DNSError); ok {
			logger.Error().
				Str("origin", originURL).
				Str("error_type", "dns").
				Err(dnsErr).
				Msg("DNS resolution failed")
			metrics.ProxyErrors.WithLabelValues(originURL, "dns").Inc()
			http.Error(w, "service unavailable: DNS error", http.StatusServiceUnavailable)
			return
		}

		// Connection errors
		if strings.Contains(err.Error(), "connection refused") {
			logger.Error().
				Str("origin", originURL).
				Str("error_type", "connection").
				Err(err).
				Msg("connection refused")
			metrics.ProxyErrors.WithLabelValues(originURL, "connection").Inc()
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		// Default to bad gateway
		logger.Error().
			Str("origin", originURL).
			Str("error_type", "other").
			Err(err).
			Msg("proxy error")
		metrics.ProxyErrors.WithLabelValues(originURL, "other").Inc()
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	// Cache the proxy with size limit and TTL
	h.proxiesMu.Lock()
	defer h.proxiesMu.Unlock()

	// Implement LRU cache eviction when at capacity
	if len(h.proxies) >= maxProxyCacheSize {
		// Evict least recently used (back of list)
		if back := h.proxiesLRU.Back(); back != nil {
			evictCP := back.Value.(*cachedProxy)
			if transport, ok := evictCP.proxy.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
			delete(h.proxies, evictCP.originURL)
			h.proxiesLRU.Remove(back)
			metrics.ProxyCacheOps.WithLabelValues("eviction").Inc()
		}
	}

	// Create cached proxy entry
	cp := &cachedProxy{
		proxy:     proxy,
		createdAt: time.Now(),
		originURL: originURL,
	}
	// Add to front of LRU list (most recently used)
	cp.lruElement = h.proxiesLRU.PushFront(cp)
	h.proxies[originURL] = cp

	return proxy
}

// Shutdown gracefully shuts down the proxy handler
func (h *Handler) Shutdown(ctx context.Context) error {
	h.proxiesMu.Lock()
	defer h.proxiesMu.Unlock()

	// Close idle connections in all transports
	for origin, cp := range h.proxies {
		if transport, ok := cp.proxy.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
			log.Info().Str("origin", origin).Msg("closed idle connections for origin")
		}
	}

	return nil
}

// serveChallengePage serves the challenge page and its assets
func (h *Handler) serveChallengePage(w http.ResponseWriter, r *http.Request) {
	// Strip challenge path prefix and clean the path
	path := strings.TrimPrefix(r.URL.Path, h.cfg.Proxy.ChallengePath)
	path = strings.TrimPrefix(path, "/")

	// URL-decode to catch encoded traversal attempts
	decodedPath, err := url.QueryUnescape(path)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Prevent directory traversal attacks (check both original and decoded)
	if strings.Contains(decodedPath, "..") || strings.Contains(path, "..") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	path = decodedPath

	if path == "" {
		path = "index.html"
	}

	// Build full path and validate it's within challenge page directory
	fullPath := path
	if !strings.HasPrefix(fullPath, "/") {
		fullPath = "/" + fullPath
	}

	// Serve file directly (safer than http.FileServer for this use case)
	http.ServeFile(w, r, h.challengePageDir+fullPath)
}

// Helper functions

// authzRecorder captures the response from the authz handler
type authzRecorder struct {
	header     http.Header
	statusCode int
	writeOnce  sync.Once
}

func (r *authzRecorder) Header() http.Header {
	return r.header
}

func (r *authzRecorder) Write(b []byte) (int, error) {
	r.writeOnce.Do(func() {
		r.statusCode = http.StatusOK
	})
	return len(b), nil
}

func (r *authzRecorder) WriteHeader(statusCode int) {
	r.writeOnce.Do(func() {
		r.statusCode = statusCode
	})
}

// getClientIP extracts the client IP from various headers
func getClientIP(r *http.Request) string {
	// Try X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])

		// Validate it's a real IP address
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return ip
		}
		// Invalid IP in XFF, fall through to RemoteAddr
	}

	// Try X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		// Validate it's a real IP address
		if parsedIP := net.ParseIP(xri); parsedIP != nil {
			return xri
		}
		// Invalid IP in X-Real-IP, fall through
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Strip port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade
func isWebSocketUpgrade(r *http.Request) bool {
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		return false
	}

	// Parse Connection header properly (it's a comma-separated list)
	conn := strings.ToLower(r.Header.Get("Connection"))
	for _, token := range strings.Split(conn, ",") {
		if strings.TrimSpace(token) == "upgrade" {
			return true
		}
	}
	return false
}

// getScheme returns the scheme (http or https) for the request
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}

	// Only trust X-Forwarded-Proto if it's a valid scheme
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		scheme = strings.ToLower(scheme)
		if scheme == "http" || scheme == "https" {
			return scheme
		}
	}

	return "http"
}

// parseCookies extracts cookies from Set-Cookie headers
func parseCookies(header http.Header) []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookieStr := range header["Set-Cookie"] {
		if parsed := parseCookie(cookieStr); parsed != nil {
			cookies = append(cookies, parsed)
		}
	}
	return cookies
}

// parseCookie parses a single Set-Cookie header value
func parseCookie(setCookie string) *http.Cookie {
	// Use a dummy request to parse the Set-Cookie header
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": []string{setCookie},
		},
	}
	cookies := resp.Cookies()
	if len(cookies) > 0 {
		return cookies[0]
	}
	return nil
}
