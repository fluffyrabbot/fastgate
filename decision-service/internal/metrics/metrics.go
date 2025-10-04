package metrics

import (
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
)

func MustRegister() {
	prometheus.MustRegister(AuthzDecision, AuthzDuration, ClearanceIssued, ChallengeStarted, ChallengeSolved, WSUpgrades, BuildInfo)
}
