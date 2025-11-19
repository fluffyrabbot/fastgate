package main

import (
	"context"
	"encoding/json"
	"flag"
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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	maxJSONBytes    = 4 * 1024  // 4KB body cap for challenge/nonce endpoint
	maxEntropyBytes = 16 * 1024 // 16KB for challenge/complete with entropy data
)

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
		Int("store_capacity", cfg.Challenge.StoreCapacity).
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


	// Challenge store (bounded LRU inside; default capacity).
	chStore := challenge.NewStore(time.Duration(cfg.Challenge.TTLSec) * time.Second)

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

		// Challenge endpoints (for PoW and WebAuthn challenges)
		mux.Handle("/v1/challenge/nonce", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleChallengeNonce(w, r, cfg, chStore, chNonceRPS)
		}))
		mux.Handle("/v1/challenge/complete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleChallengeComplete(w, r, cfg, chStore, kr)
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

		// Proxy handler for all other requests
		mux.Handle("/", proxyHandler)

		// Apply middleware chain: request ID → common headers
		handler = Chain(
			httputil.RequestIDMiddleware(log.Logger),
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
				metrics.RateLimitHits.WithLabelValues("challenge_nonce").Inc()
				w.Header().Set("Retry-After", strconv.Itoa(cfg.Challenge.RetryAfterSec))
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
				return
			}
		}

		// Mint challenge with configured difficulty & retries
		id, nonce, err := chStore.NewWithMaxRetries(cfg.Challenge.DifficultyBits, cfg.Challenge.MaxRetries)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		metrics.ChallengeStarted.Inc()

		resp := map[string]any{
			"challenge_id":    id,
			"nonce":           nonce,
			"difficulty_bits": cfg.Challenge.DifficultyBits,
			"expires_at":      time.Now().Add(time.Duration(cfg.Challenge.TTLSec) * time.Second).UTC().Format(time.RFC3339),
			"return_url":      retURL,
		}
		writeJSON(w, http.StatusOK, resp)
	}))

	// /v1/challenge/complete — validate PoW, mint clearance, redirect
	mux.Handle("/v1/challenge/complete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Atomically validate and consume
		ok, reason, _ := chStore.TrySolve(req.ChallengeID, req.Nonce, req.Solution)
		if !ok {
			// Debug logging for challenge validation failures
			if cfg.Logging.Level == "debug" {
				clientIP := clientIPFromHeaders(r)
				log.Debug().
					Str("reason", reason).
					Str("challenge_id", req.ChallengeID).
					Str("client_ip", clientIP).
					Msg("challenge validation failed")
			}

			switch reason {
			case "not_found", "expired":
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
				return
			case "invalid_nonce", "invalid_solution":
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
				return
			case "too_many_retries":
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
				return
			default:
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
				return
			}
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
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		http.SetCookie(w, httputil.BuildCookie(cfg, tokenStr))
		metrics.ChallengeSolved.Inc()

		if cfg.Logging.Level == "debug" {
			log.Debug().Str("tier", tier).Msg("clearance issued")
		}

		if retURL == "" {
			retURL = "/"
		}
		w.Header().Set("Location", retURL)
		w.WriteHeader(http.StatusFound) // 302
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

		// Apply middleware chain: request ID → common headers
		handler = Chain(
			httputil.RequestIDMiddleware(log.Logger),
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
			Int("challenge_cap", cfg.Challenge.StoreCapacity).
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

// ---- Challenge Handler Functions (for integrated mode) ----

func handleChallengeNonce(w http.ResponseWriter, r *http.Request, cfg *config.Config, chStore *challenge.Store, chNonceRPS *rate.SlidingRPS) {
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
			metrics.RateLimitHits.WithLabelValues("challenge_nonce").Inc()
			w.Header().Set("Retry-After", strconv.Itoa(cfg.Challenge.RetryAfterSec))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
	}

	// Mint challenge with configured difficulty & retries
	id, nonce, err := chStore.NewWithMaxRetries(cfg.Challenge.DifficultyBits, cfg.Challenge.MaxRetries)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	metrics.ChallengeStarted.Inc()

	resp := map[string]any{
		"challenge_id":    id,
		"nonce":           nonce,
		"difficulty_bits": cfg.Challenge.DifficultyBits,
		"expires_at":      time.Now().Add(time.Duration(cfg.Challenge.TTLSec) * time.Second).UTC().Format(time.RFC3339),
		"return_url":      retURL,
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleChallengeComplete(w http.ResponseWriter, r *http.Request, cfg *config.Config, chStore *challenge.Store, kr *token.Keyring) {
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

	// Atomically validate and consume
	ok, reason, _ := chStore.TrySolve(req.ChallengeID, req.Nonce, req.Solution)
	if !ok {
		// Debug logging for challenge validation failures
		if cfg.Logging.Level == "debug" {
			clientIP := clientIPFromHeaders(r)
			log.Debug().
				Str("reason", reason).
				Str("challenge_id", req.ChallengeID).
				Str("client_ip", clientIP).
				Msg("challenge validation failed")
		}

		switch reason {
		case "not_found", "expired":
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
			return
		case "invalid_nonce", "invalid_solution":
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
			return
		case "too_many_retries":
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": reason})
			return
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid"})
			return
		}
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	http.SetCookie(w, httputil.BuildCookie(cfg, tokenStr))
	metrics.ChallengeSolved.Inc()

	if cfg.Logging.Level == "debug" {
		log.Debug().Str("tier", tier).Msg("clearance issued")
	}

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
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
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
