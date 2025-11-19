package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fastgate/decision-service/internal/authz"
	"fastgate/decision-service/internal/challenge"
	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/entropy"
	"fastgate/decision-service/internal/httputil"
	"fastgate/decision-service/internal/intel"
	"fastgate/decision-service/internal/metrics"
	"fastgate/decision-service/internal/proxy"
	"fastgate/decision-service/internal/rate"
	"fastgate/decision-service/internal/token"
	"fastgate/decision-service/internal/webauthn"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	maxJSONBytes    = 4 * 1024  // 4KB body cap for challenge/nonce endpoint
	maxEntropyBytes = 16 * 1024 // 16KB for challenge/complete with entropy data
)

// System uptime tracking
var startTime = time.Now()

func main() {
	// CLI flag support for config path
	configFlag := flag.String("config", "", "path to config file (overrides FASTGATE_CONFIG env var)")
	flag.Parse()

	// Determine config path: CLI flag > env var > default
	cfgPath := *configFlag
	if cfgPath == "" {
		cfgPath = os.Getenv("FASTGATE_CONFIG")
	}
	if cfgPath == "" {
		// Try config.yaml first, fall back to config.example.yaml
		cfgPath = "./config.yaml"
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			// Can't use log yet, it's not configured
			cfgPath = "./config.example.yaml"
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("invalid config")
	}

	// Setup structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if cfg.Logging.Level == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Logger.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		// JSON logging for production
	}

	// Startup configuration summary
	log.Info().Msg("=== FastGate Configuration Summary ===")
	log.Info().
		Str("config_path", cfgPath).
		Str("log_level", cfg.Logging.Level).
		Str("listen", cfg.Server.Listen).
		Bool("tls_enabled", cfg.Server.TLSEnabled).
		Msg("server configuration")
	log.Info().
		Bool("enforce", cfg.Modes.Enforce).
		Bool("fail_open", cfg.Modes.FailOpen).
		Bool("under_attack", cfg.Modes.UnderAttack).
		Msg("security modes")
	log.Info().
		Int("challenge_threshold", cfg.Policy.ChallengeThreshold).
		Int("block_threshold", cfg.Policy.BlockThreshold).
		Int("difficulty_bits", cfg.Challenge.DifficultyBits).
		Int("challenge_ttl_sec", cfg.Challenge.TTLSec).
		Float64("nonce_rps_limit", cfg.Challenge.NonceRPSLimit).
		Msg("challenge configuration")
	log.Info().
		Bool("webauthn_enabled", cfg.WebAuthn.Enabled).
		Bool("threat_intel_enabled", cfg.ThreatIntel.Enabled).
		Bool("proxy_enabled", cfg.Proxy.Enabled).
		Str("proxy_mode", cfg.Proxy.Mode).
		Msg("feature flags")
	log.Info().Msg("FastGate starting...")

	kr, err := token.NewKeyring(cfg.Token.Alg, cfg.Token.Keys, cfg.Token.CurrentKID, cfg.Token.Issuer, cfg.Token.SkewSec)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create keyring")
	}
	authzHandler := authz.NewHandler(cfg, kr)

	// Stateless Challenge Issuer (replaces stateful store)
	// Use Cluster SecretKey if available, otherwise generate ephemeral random key
	issuerSecret := cfg.Cluster.SecretKey
	if issuerSecret == "" {
		log.Warn().Msg("cluster.secret_key not set; generating ephemeral secret for challenge signing (will not survive restart)")
		rnd := make([]byte, 32)
		rand.Read(rnd)
		issuerSecret = base64.RawURLEncoding.EncodeToString(rnd)
	}
	chIssuer, err := challenge.NewIssuer(issuerSecret)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create challenge issuer")
	}

	// Per-IP guard for challenge/nonce issuance.
	chNonceRPS := rate.NewSlidingRPS(10)

	// WebAuthn handler (if enabled)
	var webauthnHandler *webauthn.Handler
	if cfg.WebAuthn.Enabled {
		wh, err := webauthn.NewHandler(cfg, kr, chNonceRPS)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to create webauthn handler")
		}
		webauthnHandler = wh
		log.Info().
			Str("rp_id", cfg.WebAuthn.RPID).
			Strs("rp_origins", cfg.WebAuthn.RPOrigins).
			Msg("WebAuthn enabled")
	}

	// Threat Intelligence (if enabled)
	var intelStore *intel.Store
	var taxiiServer *intel.TAXIIServer
	var pollers []*intel.Poller
	if cfg.ThreatIntel.Enabled {
		intelStore = intel.NewStore(cfg.ThreatIntel.CacheCapacity)

		// Start TAXII server (publish)
		taxiiServer = intel.NewTAXIIServer()
		taxiiServer.RegisterCollection("fastgate", "FastGate Indicators", "L7 attack indicators")

		// Start TAXII clients (subscribe to peers)
		for _, peer := range cfg.ThreatIntel.Peers {
			client := intel.NewTAXIIClient(peer.URL, peer.Username, peer.Password)
			pollInterval := time.Duration(peer.PollIntervalSec) * time.Second
			if pollInterval <= 0 {
				pollInterval = 30 * time.Second
			}
			poller := intel.NewPoller(client, intelStore, peer.CollectionID, pollInterval)
			pollers = append(pollers, poller)
			go poller.Start()
			log.Info().
				Str("peer_name", peer.Name).
				Dur("poll_interval", pollInterval).
				Msg("threat intel poller started")
		}

		// Inject into authz handler
		authzHandler.IntelStore = intelStore
		authzHandler.TAXIIServer = taxiiServer

		log.Info().
			Int("peers", len(cfg.ThreatIntel.Peers)).
			Int("cache_capacity", cfg.ThreatIntel.CacheCapacity).
			Msg("threat intel enabled")
	}

	// Check if we're using integrated proxy mode
	var handler http.Handler
	var proxyHandler *proxy.Handler // Store reference for shutdown
	if cfg.Proxy.Enabled && cfg.Proxy.Mode == "integrated" {
		// Integrated proxy mode: all requests go through proxy handler
		log.Info().Msg("starting in integrated proxy mode")

		// Determine challenge page directory
		challengePageDir := os.Getenv("CHALLENGE_PAGE_DIR")
		if challengePageDir == "" {
			challengePageDir = "./challenge-page"
		}

		// Create integrated proxy handler
		ph, err := proxy.NewHandler(cfg, authzHandler, challengePageDir)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to create proxy handler")
		}
		proxyHandler = ph

		// Log proxy routing configuration
		log.Info().Msg("proxy routing configuration:")
		if cfg.Proxy.Origin != "" {
			log.Info().Str("origin", cfg.Proxy.Origin).Msg("  mode: single-origin")
		} else {
			log.Info().Int("route_count", len(cfg.Proxy.Routes)).Msg("  mode: multi-origin")
			for i, route := range cfg.Proxy.Routes {
				if route.Host != "" {
					log.Info().Int("index", i+1).Str("host", route.Host).Str("origin", route.Origin).Msg("    route")
				} else if route.Path != "" {
					log.Info().Int("index", i+1).Str("path", route.Path).Str("origin", route.Origin).Msg("    route")
				}
			}
		}
		log.Info().
			Str("challenge_path", cfg.Proxy.ChallengePath).
			Str("challenge_dir", challengePageDir).
			Msg("  challenge configuration")
		log.Info().
			Int("proxy_timeout_ms", cfg.Proxy.TimeoutMs).
			Int("idle_timeout_ms", cfg.Proxy.IdleTimeoutMs).
			Msg("  timeouts")

		// Create mux for API endpoints and proxy
		mux := http.NewServeMux()

		// Serve challenge page assets directly, bypassing authz
		challengeFS := http.FileServer(http.Dir(challengePageDir))
		mux.Handle(cfg.Proxy.ChallengePath+"/", http.StripPrefix(cfg.Proxy.ChallengePath, challengeFS))

		// Test/Debug endpoint - shows authentication success without requiring origin
		mux.Handle("/test/success", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleTestSuccess(w, r, cfg, kr)
		}))

		// Challenge endpoints (for PoW and WebAuthn challenges)
		mux.Handle("/v1/challenge/nonce", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleChallengeNonce(w, r, cfg, chIssuer, chNonceRPS)
		}))
		mux.Handle("/v1/challenge/complete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleChallengeComplete(w, r, cfg, chIssuer, kr)
		}))

		// WebAuthn endpoints (if enabled)
		if webauthnHandler != nil {
			mux.Handle("/v1/challenge/webauthn", http.HandlerFunc(webauthnHandler.BeginRegistration))
			mux.Handle("/v1/challenge/complete/webauthn", http.HandlerFunc(webauthnHandler.FinishRegistration))
		}

		// TAXII endpoints (if threat intel enabled)
		if taxiiServer != nil {
			mux.Handle("/taxii2/collections/", http.HandlerFunc(taxiiServer.HandleCollections))
			mux.Handle("/taxii2/collections/fastgate/objects/", http.HandlerFunc(taxiiServer.HandleObjects))
		}

		// Health & metrics endpoints
		mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHealth(w, r, proxyHandler, intelStore, webauthnHandler)
		}))
		mux.Handle("/readyz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHealth(w, r, proxyHandler, intelStore, webauthnHandler)
		}))
		metrics.MustRegister()
		mux.Handle("/metrics", promhttp.Handler())
		
		// Admin stats endpoint for dashboard
		mux.Handle("/admin/stats", http.HandlerFunc(handleAdminStats))

		// Proxy handler for all other requests
		mux.Handle("/", proxyHandler)

		// Apply middleware chain: request ID (with trusted proxies) → common headers
		handler = Chain(
			httputil.RequestIDMiddleware(log.Logger, cfg.Server.TrustedProxyCIDRs),
			withCommonHeaders,
		)(mux)
	} else {
		// NGINX mode: traditional auth_request endpoint mode
		log.Info().Msg("starting in NGINX mode (auth_request)")
		mux := http.NewServeMux()

		// /v1/authz — called via NGINX auth_request
		mux.Handle("/v1/authz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Observe mode: always allow, but run handler to issue cookies/metrics
			if !cfg.Modes.Enforce {
				rr := newResponseRecorder()
				authzHandler.ServeHTTP(rr, r)
				if sc := rr.Header().Get("Set-Cookie"); sc != "" {
					w.Header().Set("Set-Cookie", sc)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			authzHandler.ServeHTTP(w, r)
		}))

		// /v1/challenge/nonce — issue PoW nonce
		mux.Handle("/v1/challenge/nonce", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleChallengeNonce(w, r, cfg, chIssuer, chNonceRPS)
		}))

		// /v1/challenge/complete — validate PoW, mint clearance, redirect
		mux.Handle("/v1/challenge/complete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleChallengeComplete(w, r, cfg, chIssuer, kr)
		}))

		// WebAuthn endpoints (if enabled)
		if webauthnHandler != nil {
			mux.Handle("/v1/challenge/webauthn", http.HandlerFunc(webauthnHandler.BeginRegistration))
			mux.Handle("/v1/challenge/complete/webauthn", http.HandlerFunc(webauthnHandler.FinishRegistration))
			log.Info().Msg("WebAuthn endpoints registered")
		}
		// TAXII endpoints (if threat intel enabled)
		if taxiiServer != nil {
			mux.Handle("/taxii2/collections/", http.HandlerFunc(taxiiServer.HandleCollections))
			mux.Handle("/taxii2/collections/fastgate/objects/", http.HandlerFunc(taxiiServer.HandleObjects))
			log.Info().Msg("TAXII endpoints registered")
		}

		// health & metrics
		mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHealth(w, r, nil, intelStore, webauthnHandler)
		}))
		mux.Handle("/readyz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleHealth(w, r, nil, intelStore, webauthnHandler)
		}))
		metrics.MustRegister()
		mux.Handle("/metrics", promhttp.Handler())

		// Admin stats endpoint for dashboard
		mux.Handle("/admin/stats", http.HandlerFunc(handleAdminStats))

		// Apply middleware chain: request ID (with trusted proxies) → common headers
		handler = Chain(
			httputil.RequestIDMiddleware(log.Logger, cfg.Server.TrustedProxyCIDRs),
			withCommonHeaders,
		)(mux)
	}

	// Log feature state summary
	log.Info().
		Bool("enforce", cfg.Modes.Enforce).
		Bool("fail_open", cfg.Modes.FailOpen).
		Bool("under_attack", cfg.Modes.UnderAttack).
		Bool("webauthn", cfg.WebAuthn.Enabled).
		Bool("threat_intel", cfg.ThreatIntel.Enabled).
		Str("proxy_mode", cfg.Proxy.Mode).
		Msg("feature configuration")

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           handler,
		ReadHeaderTimeout: time.Duration(cfg.Server.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       90 * time.Second,
	}

	// Graceful shutdown setup
	serverErrors := make(chan error, 1)
	go func() {
		log.Info().
			Str("listen", cfg.Server.Listen).
			Int("difficulty", cfg.Challenge.DifficultyBits).
			Float64("rps_guard", cfg.Challenge.NonceRPSLimit).
			Msg("FastGate Decision Service listening")
		if cfg.Server.TLSEnabled {
			log.Info().
				Str("cert", cfg.Server.TLSCertFile).
				Str("key", cfg.Server.TLSKeyFile).
				Msg("starting with TLS")
			serverErrors <- srv.ListenAndServeTLS(cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile)
		} else {
			log.Warn().Msg("starting without TLS (WARNING: use TLS in production)")
			serverErrors <- srv.ListenAndServe()
		}
	}()

	// Signal handler for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatal().Err(err).Msg("server error")
	case sig := <-shutdown:
		log.Info().Str("signal", sig.String()).Msg("received shutdown signal")

		// Create shutdown context with 30s timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Stop pollers
		for _, p := range pollers {
			p.Stop()
		}

		// Close intel store
		if intelStore != nil {
			intelStore.Close()
		}

		// Shutdown authz handler (stop WebSocket timers)
		if authzHandler != nil {
			authzHandler.Shutdown()
		}

		// Shutdown proxy handler (if in integrated mode)
		if proxyHandler != nil {
			if err := proxyHandler.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msg("proxy shutdown error")
			}
		}

		// Gracefully shutdown HTTP server
		if err := srv.Shutdown(ctx); err != nil {
			log.Warn().Err(err).Msg("graceful shutdown failed, forcing close")
			srv.Close()
		}

		log.Info().Msg("shutdown complete")
	}
}

// handleAdminStats aggregates metrics into a JSON summary for the admin dashboard
func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	// Gather metrics from Prometheus registry
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "metrics_error"})
		return
	}

	stats := make(map[string]map[string]any)
	stats["decisions"] = make(map[string]any)
	stats["challenges"] = make(map[string]any)
	stats["webauthn"] = make(map[string]any)
	stats["proxy"] = make(map[string]any)
	stats["system"] = make(map[string]any)

	// Helper to find a metric family by name
	findMF := func(name string) *dto.MetricFamily {
		for _, mf := range mfs {
			if mf.GetName() == name {
				return mf
			}
		}
		return nil
	}

	// 1. Decisions
	if mf := findMF("fastgate_authz_decision_total"); mf != nil {
		for _, m := range mf.Metric {
			for _, label := range m.Label {
				if label.GetName() == "action" {
					stats["decisions"][label.GetValue()] = m.Counter.GetValue()
				}
			}
		}
	}
	if mf := findMF("fastgate_invalid_tokens_total"); mf != nil {
		if len(mf.Metric) > 0 {
			stats["decisions"]["invalid_tokens"] = mf.Metric[0].Counter.GetValue()
		}
	}

	// 2. Challenges
	if mf := findMF("fastgate_challenge_started_total"); mf != nil {
		if len(mf.Metric) > 0 {
			stats["challenges"]["started"] = mf.Metric[0].Counter.GetValue()
		}
	}
	if mf := findMF("fastgate_challenge_solved_total"); mf != nil {
		if len(mf.Metric) > 0 {
			stats["challenges"]["solved"] = mf.Metric[0].Counter.GetValue()
		}
	}

	// 3. WebAuthn
	if mf := findMF("fastgate_webauthn_attestation_total"); mf != nil {
		success := 0.0
		failed := 0.0
		for _, m := range mf.Metric {
			val := m.Counter.GetValue()
			for _, label := range m.Label {
				if label.GetName() == "result" {
					if label.GetValue() == "success" {
						success += val
					} else {
						failed += val
					}
				}
			}
		}
		stats["webauthn"]["success"] = success
		stats["webauthn"]["failed"] = failed
	}
	if mf := findMF("fastgate_rate_limit_hits_total"); mf != nil {
		for _, m := range mf.Metric {
			for _, label := range m.Label {
				if label.GetName() == "endpoint" {
					if label.GetValue() == "webauthn_begin" {
						stats["webauthn"]["rate_limit_begin"] = m.Counter.GetValue()
					}
				}
			}
		}
	}

	// 4. Proxy
	if mf := findMF("fastgate_proxy_errors_total"); mf != nil {
		totalErrors := 0.0
		for _, m := range mf.Metric {
			totalErrors += m.Counter.GetValue()
		}
		stats["proxy"]["errors"] = totalErrors
	}
	if mf := findMF("fastgate_proxy_cache_size"); mf != nil {
		if len(mf.Metric) > 0 {
			stats["proxy"]["cache_size"] = mf.Metric[0].Gauge.GetValue()
		}
	}

	// 5. System
	if mf := findMF("go_goroutines"); mf != nil {
		if len(mf.Metric) > 0 {
			stats["system"]["goroutines"] = mf.Metric[0].Gauge.GetValue()
		}
	}
	stats["system"]["uptime_sec"] = time.Since(startTime).Seconds()

	writeJSON(w, http.StatusOK, stats)
}

// ---- Challenge Handler Functions (for integrated mode) ----

func handleChallengeNonce(w http.ResponseWriter, r *http.Request, cfg *config.Config, chIssuer *challenge.StatelessIssuer, chNonceRPS *rate.SlidingRPS) {
	// Get request ID and logger from context for distributed tracing
	requestID := httputil.GetRequestID(r.Context())
	logger := httputil.GetLogger(r.Context())

	// Method & body caps
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBytes)
	defer r.Body.Close()

	type Req struct {
		ReturnURL string `json:"return_url"`
	}
	var req Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	retURL := sanitizeReturnURL(req.ReturnURL)

	// Per-IP RPS guard
	ip := clientIPFromHeaders(r)
	if ip != "" {
		if rps := chNonceRPS.Add("nonce:" + ip); rps > cfg.Challenge.NonceRPSLimit {
			logger.Warn().
				Str("request_id", requestID).
				Str("client_ip", ip).
				Float64("rps", rps).
				Msg("challenge nonce rate limit exceeded")
			metrics.RateLimitHits.WithLabelValues("challenge_nonce").Inc()
			w.Header().Set("Retry-After", strconv.Itoa(cfg.Challenge.RetryAfterSec))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
	}

	// Mint challenge with configured difficulty & retries
	token, nonce, err := chIssuer.Issue(cfg.Challenge.DifficultyBits, time.Duration(cfg.Challenge.TTLSec)*time.Second, ip)
	if err != nil {
		logger.Error().
			Str("request_id", requestID).
			Err(err).
			Msg("failed to issue challenge")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	metrics.ChallengeStarted.Inc()

	logger.Debug().
		Str("request_id", requestID).
		Str("client_ip", ip).
		Int("difficulty_bits", cfg.Challenge.DifficultyBits).
		Msg("challenge nonce issued")

	resp := map[string]any{
		"challenge_id":    token, // Stateless: ID is the signed token
		"nonce":           nonce,
		"difficulty_bits": cfg.Challenge.DifficultyBits,
		"expires_at":      time.Now().Add(time.Duration(cfg.Challenge.TTLSec) * time.Second).UTC().Format(time.RFC3339),
		"return_url":      retURL,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleChallengeComplete(w http.ResponseWriter, r *http.Request, cfg *config.Config, chIssuer *challenge.StatelessIssuer, kr *token.Keyring) {
	// Get request ID and logger from context for distributed tracing
	requestID := httputil.GetRequestID(r.Context())
	logger := httputil.GetLogger(r.Context())

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEntropyBytes) // Allow larger payloads for entropy data
	defer r.Body.Close()

	type Req struct {
		ChallengeID string                `json:"challenge_id"`
		Nonce       string                `json:"nonce"`
		Solution    uint32                `json:"solution"`
		ReturnURL   string                `json:"return_url"`
		UAHints     map[string]any        `json:"ua_hints"`
		Entropy     *entropy.Profile      `json:"entropy,omitempty"`
	}
	var req Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().
			Str("request_id", requestID).
			Err(err).
			Msg("invalid JSON in challenge complete")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}
	if req.ChallengeID == "" || req.Nonce == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing_fields"})
		return
	}

	// Validate entropy payload to prevent DoS via unbounded arrays
	if req.Entropy != nil {
		const maxAnomalies = 50 // Reasonable upper bound for anomaly counts
		if len(req.Entropy.Anomalies.Hardware) > maxAnomalies ||
			len(req.Entropy.Anomalies.Behavioral) > maxAnomalies ||
			len(req.Entropy.Anomalies.Environment) > maxAnomalies {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too_many_anomalies"})
			return
		}
	}

	retURL := sanitizeReturnURL(req.ReturnURL)
	clientIP := clientIPFromHeaders(r)

	// Verify JWS token (stateless)
	ok, reason, _ := chIssuer.Verify(req.ChallengeID, req.Solution, clientIP)
	if !ok {
		// Security event logging with full context
		logger.Warn().
			Str("request_id", requestID).
			Str("reason", reason).
			Str("client_ip", clientIP).
			Str("user_agent", r.Header.Get("User-Agent")).
			Msg("challenge validation failed")

		writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
		return
	}

	// Success — analyze entropy and issue clearance cookie
	tier := "low" // Default tier for PoW completion

	// Analyze entropy if provided
	if req.Entropy != nil {
		analyzer := entropy.NewAnalyzer()
		assessment := analyzer.Analyze(req.Entropy)

		if cfg.Logging.Level == "debug" {
			log.Debug().
				Float64("bot_score", assessment.BotScore).
				Float64("confidence", assessment.Confidence).
				Bool("suspicious", assessment.IsSuspicious).
				Interface("reasons", assessment.Reasons).
				Msg("entropy assessment")
		}

		// Upgrade tier if low bot score and high confidence
		if !assessment.IsSuspicious && assessment.Confidence >= 0.5 {
			tier = "medium" // Upgrade to medium for human-like behavior
		}

		// Downgrade tier if high bot score
		if assessment.IsBot {
			tier = "low" // Keep low tier for bot-like behavior
			if cfg.Logging.Level == "debug" {
				log.Debug().
					Float64("bot_score", assessment.BotScore).
					Interface("reasons", assessment.Reasons).
					Msg("bot detected")
			}
		}
	}

	tokenStr, err := kr.Sign(tier, cfg.CookieMaxAge())
	if err != nil {
		logger.Error().
			Str("request_id", requestID).
			Err(err).
			Msg("failed to sign clearance token")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	http.SetCookie(w, httputil.BuildCookie(cfg, tokenStr))
	metrics.ChallengeSolved.Inc()

	logger.Info().
		Str("request_id", requestID).
		Str("tier", tier).
		Str("client_ip", clientIP).
		Msg("clearance issued")

	if retURL == "" {
		retURL = "/"
	}
	w.Header().Set("Location", retURL)
	w.WriteHeader(http.StatusFound) // 302
}

// ---- Helpers ----

// Middleware wraps an http.Handler and returns a new handler
type Middleware func(http.Handler) http.Handler

// Chain composes multiple middlewares into a single middleware
// Middlewares are applied in the order they are provided:
// Chain(mw1, mw2, mw3)(handler) => mw1(mw2(mw3(handler)))
func Chain(middlewares ...Middleware) Middleware {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security & cache headers
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Only set HSTS if TLS is enabled
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// CSP for API endpoints (not proxied content)
		if strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/taxii2/") || strings.HasPrefix(r.URL.Path, "/metrics") {
			w.Header().Set("Content-Security-Policy", "default-src 'none'; connect-src 'self'; frame-ancestors 'none'")
		}

		next.ServeHTTP(w, r)
	})
}

// Use httputil package for shared helpers
var (
	writeJSON           = httputil.WriteJSON
	sanitizeReturnURL   = httputil.SanitizeReturnURL
	clientIPFromHeaders = httputil.ClientIPFromHeaders
)

// responseRecorder for observe mode in /v1/authz wrapper.
type responseRecorder struct{ h http.Header }

func newResponseRecorder() *responseRecorder                  { return &responseRecorder{h: make(http.Header)} }
func (r *responseRecorder) Header() http.Header               { return r.h }
func (r *responseRecorder) Write(b []byte) (int, error)       { return len(b), nil }
func (r *responseRecorder) WriteHeader(statusCode int)        {}

// handleHealth returns detailed component health status
// handleTestSuccess shows authentication success page for testing without requiring origin
func handleTestSuccess(w http.ResponseWriter, r *http.Request, cfg *config.Config, kr *token.Keyring) {
	// Parse the clearance token if present
	var tokenInfo struct {
		Valid      bool
		Tier       string
		Expiry     string
		Error      string
		Present    bool
	}

	cookie, err := r.Cookie(cfg.Cookie.Name)
	if err != nil {
		tokenInfo.Present = false
		tokenInfo.Error = "No clearance cookie found"
	} else {
		tokenInfo.Present = true
		claims, _, err := kr.Verify(cookie.Value, 0) // 0 = no clock skew tolerance needed for display
		if err != nil {
			tokenInfo.Valid = false
			tokenInfo.Error = err.Error()
		} else {
			tokenInfo.Valid = true
			tokenInfo.Tier = claims.Tier
			tokenInfo.Expiry = claims.ExpiresAt.Time.Format("2006-01-02 15:04:05 MST")
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Build status indicators
	statusIcon := "✅"
	statusText := "Authenticated"
	statusClass := "success"
	if !tokenInfo.Valid {
		statusIcon = "⚠️"
		statusText = "Invalid/Missing Token"
		statusClass = "warning"
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>FastGate Test Success</title>
	<meta charset="utf-8">
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
			background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 20px;
		}
		.container {
			background: white;
			border-radius: 16px;
			box-shadow: 0 20px 60px rgba(0,0,0,0.3);
			max-width: 800px;
			width: 100%%;
			padding: 40px;
		}
		.header {
			text-align: center;
			margin-bottom: 40px;
		}
		.status-icon {
			font-size: 64px;
			margin-bottom: 16px;
		}
		h1 {
			color: #1a202c;
			font-size: 32px;
			margin-bottom: 8px;
		}
		.subtitle {
			color: #718096;
			font-size: 16px;
		}
		.info-box {
			background: #f7fafc;
			border-left: 4px solid #4299e1;
			padding: 20px;
			margin: 24px 0;
			border-radius: 4px;
		}
		.info-box.success {
			border-left-color: #48bb78;
			background: #f0fff4;
		}
		.info-box.warning {
			border-left-color: #ed8936;
			background: #fffaf0;
		}
		.info-row {
			display: flex;
			padding: 12px 0;
			border-bottom: 1px solid #e2e8f0;
		}
		.info-row:last-child {
			border-bottom: none;
		}
		.info-label {
			font-weight: 600;
			color: #2d3748;
			min-width: 180px;
		}
		.info-value {
			color: #4a5568;
			font-family: 'SF Mono', Monaco, 'Courier New', monospace;
			word-break: break-all;
		}
		.token-tier {
			display: inline-block;
			padding: 4px 12px;
			border-radius: 12px;
			font-size: 12px;
			font-weight: 600;
			text-transform: uppercase;
			background: #9f7aea;
			color: white;
		}
		.explanation {
			background: #edf2f7;
			padding: 24px;
			border-radius: 8px;
			margin: 24px 0;
		}
		.explanation h2 {
			color: #2d3748;
			font-size: 18px;
			margin-bottom: 16px;
		}
		.explanation p {
			color: #4a5568;
			line-height: 1.6;
			margin-bottom: 12px;
		}
		.flow-list {
			list-style: none;
			counter-reset: step;
		}
		.flow-list li {
			counter-increment: step;
			padding: 12px 0;
			color: #4a5568;
			position: relative;
			padding-left: 40px;
		}
		.flow-list li::before {
			content: counter(step);
			position: absolute;
			left: 0;
			top: 10px;
			width: 28px;
			height: 28px;
			background: #667eea;
			color: white;
			border-radius: 50%%;
			display: flex;
			align-items: center;
			justify-content: center;
			font-weight: 600;
			font-size: 14px;
		}
		.note {
			background: #fff5f5;
			border: 1px solid #feb2b2;
			padding: 16px;
			border-radius: 8px;
			margin-top: 24px;
		}
		.note strong {
			color: #c53030;
		}
		.note p {
			color: #742a2a;
			margin-top: 8px;
			line-height: 1.5;
		}
		code {
			background: #1a202c;
			color: #68d391;
			padding: 2px 6px;
			border-radius: 3px;
			font-size: 13px;
		}
		.links {
			margin-top: 32px;
			padding-top: 24px;
			border-top: 2px solid #e2e8f0;
			text-align: center;
		}
		.links a {
			color: #667eea;
			text-decoration: none;
			margin: 0 16px;
			font-weight: 500;
		}
		.links a:hover {
			text-decoration: underline;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<div class="status-icon">%s</div>
			<h1>%s</h1>
			<p class="subtitle">FastGate Authentication Test Page</p>
		</div>

		<div class="info-box %s">
			<div class="info-row">
				<span class="info-label">Cookie Present:</span>
				<span class="info-value">%v</span>
			</div>
			<div class="info-row">
				<span class="info-label">Token Valid:</span>
				<span class="info-value">%v</span>
			</div>`,
		statusIcon, statusText, statusClass,
		tokenInfo.Present, tokenInfo.Valid)

	if tokenInfo.Valid {
		html += fmt.Sprintf(`
			<div class="info-row">
				<span class="info-label">Token Tier:</span>
				<span class="info-value"><span class="token-tier">%s</span></span>
			</div>
			<div class="info-row">
				<span class="info-label">Expires:</span>
				<span class="info-value">%s</span>
			</div>`, tokenInfo.Tier, tokenInfo.Expiry)
	}

	if tokenInfo.Error != "" {
		html += fmt.Sprintf(`
			<div class="info-row">
				<span class="info-label">Error:</span>
				<span class="info-value">%s</span>
			</div>`, tokenInfo.Error)
	}

	html += `
		</div>

		<div class="explanation">
			<h2>What Just Happened:</h2>
			<ol class="flow-list">
				<li>Your request was intercepted by FastGate</li>
				<li>You were redirected to the challenge page (<code>/__uam</code>)</li>
				<li>WebAuthn registration flow executed with your platform authenticator</li>
				<li>FastGate verified your attestation and issued a clearance token</li>
				<li>You were redirected here with the authenticated session</li>
			</ol>
		</div>

		<div class="note">
			<strong>⚙️ Development Mode Notice</strong>
			<p>
				This test endpoint exists to verify authentication without requiring a production origin server.
				Once you configure your production origin (in <code>config.yaml</code> under <code>proxy.origin</code>),
				authenticated requests will be proxied to your backend application instead of showing this page.
			</p>
			<p style="margin-top: 12px;">
				In production, users would see your actual application content here, not this test page.
				This endpoint is useful for development, debugging, and CI/CD testing.
			</p>
		</div>

		<div class="links">
			<a href="/">← Try Root Path</a>
			<a href="/test/success">Refresh This Page</a>
			<a href="/metrics">View Metrics →</a>
		</div>
	</div>
</body>
</html>`

	w.Write([]byte(html))
}

func handleHealth(w http.ResponseWriter, r *http.Request, ph *proxy.Handler, is *intel.Store, wh *webauthn.Handler) {
	type HealthStatus struct {
		Status     string            `json:"status"` // "ok" | "degraded"
		Components map[string]string `json:"components"`
	}

	status := HealthStatus{
		Status:     "ok",
		Components: make(map[string]string),
	}

	// Check proxy handler (integrated mode only)
	if ph != nil {
		status.Components["proxy"] = "ok"
	}

	// Check threat intel store
	if is != nil {
		// Intel store is always available once created
		status.Components["threat_intel"] = "ok"
	}

	// Check WebAuthn handler
	if wh != nil {
		status.Components["webauthn"] = "ok"
	}

	// Core components always available
	status.Components["authz"] = "ok"
	status.Components["challenge_store"] = "ok"

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}