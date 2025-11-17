package main

import (
	"context"
	"encoding/json"
	"log"
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
	"fastgate/decision-service/internal/rate"
	"fastgate/decision-service/internal/token"
	"fastgate/decision-service/internal/webauthn"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	maxJSONBytes                 = 4 * 1024  // 4KB body cap for challenge/nonce endpoint
	maxEntropyBytes              = 16 * 1024 // 16KB for challenge/complete with entropy data
	maxChallengeStartsRPSPerIP   = 3.0       // soft guard: ~3 req/sec per IP over 10s window
	challengeRetryAfterSeconds   = 2        // hint for clients when 429 is returned
	minClearanceRemaining        = 2 * time.Minute
	defaultWSLease               = 120 * time.Second
	defaultChallengeStoreCap     = 100_000 // (used implicitly by Store's default)
)

func main() {
	cfgPath := os.Getenv("FASTGATE_CONFIG")
	if cfgPath == "" {
		// Try config.yaml first, fall back to config.example.yaml
		cfgPath = "./config.yaml"
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			log.Printf("No config file found at %s, using config.example.yaml", cfgPath)
			cfgPath = "./config.example.yaml"
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	kr, err := token.NewKeyring(cfg.Token.Alg, cfg.Token.Keys, cfg.Token.CurrentKID, cfg.Token.Issuer, cfg.Token.SkewSec)
	if err != nil {
		log.Fatalf("keyring: %v", err)
	}
	authzHandler := authz.NewHandler(cfg, kr)

// Production attestation via redemption service (if enabled and dev not forced)
// TODO: Implement Privacy Pass attestation
/*
if os.Getenv("FASTGATE_DEV_ATTEST") != "1" && cfg.Attestation.Enabled && cfg.Attestation.Provider == "privpass" {
    log.Printf("Attestation enabled but not yet implemented (provider=%s)", cfg.Attestation.Provider)
}
*/

	// Challenge store (bounded LRU inside; default capacity).
	chStore := challenge.NewStore(time.Duration(cfg.Challenge.TTLSec) * time.Second)

	// Per-IP guard for challenge/nonce issuance.
	chNonceRPS := rate.NewSlidingRPS(10)

	// WebAuthn handler (if enabled)
	var webauthnHandler *webauthn.Handler
	if cfg.WebAuthn.Enabled {
		wh, err := webauthn.NewHandler(cfg, kr, chNonceRPS)
		if err != nil {
			log.Fatalf("webauthn handler: %v", err)
		}
		webauthnHandler = wh
		log.Printf("WebAuthn enabled (RP ID: %s, Origins: %v)", cfg.WebAuthn.RPID, cfg.WebAuthn.RPOrigins)
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
			log.Printf("Threat intel: polling %s every %v", peer.Name, pollInterval)
		}

		// Inject into authz handler
		authzHandler.IntelStore = intelStore
		authzHandler.TAXIIServer = taxiiServer

		log.Printf("Threat intel enabled (peers: %d, cache: %d)", len(cfg.ThreatIntel.Peers), cfg.ThreatIntel.CacheCapacity)
	}

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
			if rps := chNonceRPS.Add("nonce:" + ip); rps > maxChallengeStartsRPSPerIP {
				metrics.RateLimitHits.WithLabelValues("challenge_nonce").Inc()
				w.Header().Set("Retry-After", strconv.Itoa(challengeRetryAfterSeconds))
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
				log.Printf("Challenge validation failed: reason=%s id=%s ip=%s", reason, req.ChallengeID, clientIP)
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
				log.Printf("Entropy assessment: bot=%.2f confidence=%.2f suspicious=%v reasons=%v",
					assessment.BotScore, assessment.Confidence, assessment.IsSuspicious, assessment.Reasons)
			}

			// Upgrade tier if low bot score and high confidence
			if !assessment.IsSuspicious && assessment.Confidence >= 0.5 {
				tier = "medium" // Upgrade to medium for human-like behavior
			}

			// Downgrade tier if high bot score
			if assessment.IsBot {
				tier = "low" // Keep low tier for bot-like behavior
				if cfg.Logging.Level == "debug" {
					log.Printf("Bot detected (score=%.2f): %v", assessment.BotScore, assessment.Reasons)
				}
			}
		}

		tokenStr, err := kr.Sign(tier, cfg.CookieMaxAge())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		http.SetCookie(w, buildCookie(cfg, tokenStr))
		metrics.ChallengeSolved.Inc()

		if cfg.Logging.Level == "debug" {
			log.Printf("Clearance issued: tier=%s", tier)
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
		log.Printf("WebAuthn endpoints registered: /v1/challenge/webauthn, /v1/challenge/complete/webauthn")
	}

	// TAXII endpoints (if threat intel enabled)
	if taxiiServer != nil {
		mux.Handle("/taxii2/collections/", http.HandlerFunc(taxiiServer.HandleCollections))
		mux.Handle("/taxii2/collections/fastgate/objects/", http.HandlerFunc(taxiiServer.HandleObjects))
		log.Printf("TAXII endpoints registered: /taxii2/collections/, /taxii2/collections/fastgate/objects/")
	}

	// health & metrics
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.Handle("/readyz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	metrics.MustRegister()
	mux.Handle("/metrics", promhttp.Handler())

	// Log feature state summary
	log.Printf("Feature configuration: enforce=%v fail_open=%v under_attack=%v webauthn=%v threat_intel=%v",
		cfg.Modes.Enforce, cfg.Modes.FailOpen, cfg.Modes.UnderAttack, cfg.WebAuthn.Enabled, cfg.ThreatIntel.Enabled)

	srv := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           withCommonHeaders(mux),
		ReadHeaderTimeout: time.Duration(cfg.Server.ReadTimeoutMs) * time.Millisecond,
		WriteTimeout:      time.Duration(cfg.Server.WriteTimeoutMs) * time.Millisecond,
		IdleTimeout:       90 * time.Second,
	}

	// Graceful shutdown setup
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("FastGate Decision Service listening on %s (challenge cap ~%dk, RPS guard %.1f/s per IP)", cfg.Server.Listen, defaultChallengeStoreCap/1000, maxChallengeStartsRPSPerIP)
		serverErrors <- srv.ListenAndServe()
	}()

	// Signal handler for graceful shutdown
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)
	case sig := <-shutdown:
		log.Printf("Received shutdown signal: %v", sig)

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

		// Gracefully shutdown HTTP server
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed, forcing: %v", err)
			srv.Close()
		}

		log.Println("Shutdown complete")
	}
}

// ---- Helpers ----

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security & cache headers for API endpoints
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
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

// Cookie builder (duplicate of authz helper for isolation)
func buildCookie(cfg *config.Config, tokenStr string) *http.Cookie {
	c := &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    tokenStr,
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
