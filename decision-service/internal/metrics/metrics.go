package metrics

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	AuthzDecision = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_authz_decision_total",
			Help: "Count of decisions (allow/challenge/block)",
		},
		[]string{"action"},
	)
	AuthzDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "fastgate_authz_duration_seconds",
			Help:    "Latency of /v1/authz",
			Buckets: []float64{0.005,0.01,0.025,0.05,0.1,0.25,0.5,1,2},
		},
	)
	ClearanceIssued = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "fastgate_clearance_issued_total",
			Help: "Clearance tokens minted",
		},
	)
	ChallengeStarted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "fastgate_challenge_started_total",
			Help: "Challenges started",
		},
	)
	ChallengeSolved = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "fastgate_challenge_solved_total",
			Help: "Challenges solved",
		},
	)
	ChallengeStoreSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fastgate_challenge_store_size",
			Help: "Current number of challenges in store",
		},
	)
	WSUpgrades = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_ws_upgrades_total",
			Help: "WebSocket upgrades outcome",
		},
		[]string{"result"},
	)
	BuildInfo = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fastgate_build_info",
			Help: "Build info gauge with const labels",
			ConstLabels: prometheus.Labels{"version": "0.1.0"},
		},
	)

	// Security event metrics
	RateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_rate_limit_hits_total",
			Help: "Count of rate limit hits by endpoint",
		},
		[]string{"endpoint"},
	)
	WebAuthnAttestation = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_webauthn_attestation_total",
			Help: "WebAuthn attestation outcomes",
		},
		[]string{"result", "tier"},
	)
	ThreatIntelMatches = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_threat_intel_matches_total",
			Help: "Threat intelligence matches by type",
		},
		[]string{"indicator_type", "source"},
	)
	InvalidTokens = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "fastgate_invalid_tokens_total",
			Help: "Count of invalid clearance tokens",
		},
	)

	// Proxy metrics (integrated mode)
	ProxyLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "fastgate_proxy_duration_seconds",
			Help:    "Proxy request latency by origin",
			Buckets: []float64{0.01, 0.05, 0.1, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"origin"},
	)
	ProxyErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_proxy_errors_total",
			Help: "Proxy errors by origin and error type",
		},
		[]string{"origin", "error_type"}, // error_type: timeout, dns, connection, context, other
	)
	ProxyCacheOps = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_proxy_cache_total",
			Help: "Proxy cache operations",
		},
		[]string{"operation"}, // operation: hit, miss, eviction, expiration
	)
	ProxyCacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "fastgate_proxy_cache_size",
			Help: "Current number of cached reverse proxies",
		},
	)

	// Circuit breaker metrics
	ProxyCircuitState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fastgate_proxy_circuit_state",
			Help: "Circuit breaker state by origin (0=closed, 1=open, 2=half-open)",
		},
		[]string{"origin"},
	)
	ProxyCircuitOpen = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_proxy_circuit_open_total",
			Help: "Count of requests rejected due to open circuit breaker",
		},
		[]string{"origin"},
	)
	ProxyCircuitTransitions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_proxy_circuit_transitions_total",
			Help: "Circuit breaker state transitions by origin",
		},
		[]string{"origin", "from_state", "to_state"},
	)
	ProxyCircuitOpens = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_proxy_circuit_opens_total",
			Help: "Total number of times circuit breaker opened by origin",
		},
		[]string{"origin"},
	)
	ProxyCircuitHalfOpenProbes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "fastgate_proxy_circuit_halfopen_probes_total",
			Help: "Number of probe requests allowed in half-open state",
		},
		[]string{"origin"},
	)
)

func MustRegister() {
	collectors := []prometheus.Collector{
		AuthzDecision,
		AuthzDuration,
		ClearanceIssued,
		ChallengeStarted,
		ChallengeSolved,
		ChallengeStoreSize,
		WSUpgrades,
		BuildInfo,
		RateLimitHits,
		WebAuthnAttestation,
		ThreatIntelMatches,
		InvalidTokens,
		ProxyLatency,
		ProxyErrors,
		ProxyCacheOps,
		ProxyCacheSize,
		ProxyCircuitState,
		ProxyCircuitOpen,
		ProxyCircuitTransitions,
		ProxyCircuitOpens,
		ProxyCircuitHalfOpenProbes,
	}

	for _, c := range collectors {
		if err := prometheus.Register(c); err != nil {
			// Ignore AlreadyRegisteredError (happens on restart in tests)
			if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
				log.Fatalf("Failed to register metric: %v", err)
			}
		}
	}
}
