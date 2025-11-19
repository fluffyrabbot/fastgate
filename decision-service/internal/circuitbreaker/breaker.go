package circuitbreaker

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"fastgate/decision-service/internal/metrics"

	"github.com/rs/zerolog/log"
)

// State represents the circuit breaker state
type State int32

const (
	// StateClosed - normal operation, requests flow through
	StateClosed State = iota
	// StateOpen - circuit is open, requests fail fast
	StateOpen
	// StateHalfOpen - testing if backend recovered
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Config holds circuit breaker configuration
type Config struct {
	// FailureThreshold is the number of consecutive failures before opening
	FailureThreshold int
	// SuccessThreshold is the number of consecutive successes in half-open before closing
	SuccessThreshold int
	// Timeout is how long to wait in open state before attempting half-open
	Timeout time.Duration
	// MinimumRequestThreshold is minimum requests in window before tripping
	MinimumRequestThreshold int
	// SlidingWindowSize is the time window for tracking failures
	SlidingWindowSize time.Duration
}

// DefaultConfig returns sensible defaults for a circuit breaker
func DefaultConfig() Config {
	return Config{
		FailureThreshold:        5,               // Open after 5 consecutive failures
		SuccessThreshold:        2,               // Close after 2 consecutive successes
		Timeout:                 30 * time.Second, // Try recovery after 30s
		MinimumRequestThreshold: 3,               // Need at least 3 requests to trip
		SlidingWindowSize:       10 * time.Second, // 10s sliding window
	}
}

// CircuitBreaker implements the circuit breaker pattern for a single backend
type CircuitBreaker struct {
	name   string
	config Config

	state         atomic.Int32 // State (using atomic for lock-free reads)
	failures      atomic.Int32 // Consecutive failure count
	successes     atomic.Int32 // Consecutive success count (in half-open)
	requests      atomic.Int32 // Total requests in current window
	lastFailTime  atomic.Int64 // Unix nano timestamp of last failure
	lastStateTime atomic.Int64 // Unix nano timestamp of last state change

	mu sync.RWMutex // Protects state transitions
}

// New creates a new circuit breaker for a backend
func New(name string, config Config) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:   name,
		config: config,
	}
	cb.state.Store(int32(StateClosed))
	cb.lastStateTime.Store(time.Now().UnixNano())

	// Initialize Prometheus metric
	metrics.ProxyCircuitState.WithLabelValues(name).Set(float64(StateClosed))

	return cb
}

// Allow checks if a request is allowed to proceed
func (cb *CircuitBreaker) Allow() error {
	state := State(cb.state.Load())

	switch state {
	case StateClosed:
		// Normal operation
		cb.requests.Add(1)
		return nil

	case StateOpen:
		// Check if timeout has elapsed
		now := time.Now()
		lastFail := time.Unix(0, cb.lastFailTime.Load())

		if now.Sub(lastFail) >= cb.config.Timeout {
			// Attempt transition to half-open
			cb.mu.Lock()
			// Double-check state hasn't changed
			if State(cb.state.Load()) == StateOpen {
				cb.transitionTo(StateHalfOpen)
				cb.mu.Unlock()
				cb.requests.Add(1)
				return nil
			}
			cb.mu.Unlock()
		}

		return fmt.Errorf("circuit breaker open for %s", cb.name)

	case StateHalfOpen:
		// Allow limited requests to test backend health
		cb.requests.Add(1)
		return nil

	default:
		return fmt.Errorf("circuit breaker in unknown state")
	}
}

// RecordSuccess records a successful request
func (cb *CircuitBreaker) RecordSuccess() {
	state := State(cb.state.Load())

	switch state {
	case StateClosed:
		// Reset failure count on success
		cb.failures.Store(0)

	case StateHalfOpen:
		// Increment success counter
		successes := cb.successes.Add(1)

		// Check if we've hit success threshold
		if int(successes) >= cb.config.SuccessThreshold {
			cb.mu.Lock()
			// Double-check we're still in half-open
			if State(cb.state.Load()) == StateHalfOpen {
				cb.transitionTo(StateClosed)
				cb.failures.Store(0)
				cb.successes.Store(0)
				log.Info().
					Str("backend", cb.name).
					Int("successes", int(successes)).
					Msg("circuit breaker recovered")
			}
			cb.mu.Unlock()
		}

	case StateOpen:
		// Shouldn't happen, but handle gracefully
		log.Warn().
			Str("backend", cb.name).
			Msg("received success while circuit breaker open")
	}
}

// RecordFailure records a failed request
func (cb *CircuitBreaker) RecordFailure() {
	now := time.Now()
	cb.lastFailTime.Store(now.UnixNano())

	state := State(cb.state.Load())

	switch state {
	case StateClosed:
		failures := cb.failures.Add(1)
		requests := cb.requests.Load()

		// Check if we should open the circuit
		if int(failures) >= cb.config.FailureThreshold &&
		   int(requests) >= cb.config.MinimumRequestThreshold {
			cb.mu.Lock()
			// Double-check state hasn't changed
			if State(cb.state.Load()) == StateClosed {
				cb.transitionTo(StateOpen)
				log.Error().
					Str("backend", cb.name).
					Int("failures", int(failures)).
					Int("requests", int(requests)).
					Msg("circuit breaker opened")
			}
			cb.mu.Unlock()
		}

	case StateHalfOpen:
		// Any failure in half-open immediately reopens circuit
		cb.mu.Lock()
		if State(cb.state.Load()) == StateHalfOpen {
			cb.transitionTo(StateOpen)
			cb.successes.Store(0)
			log.Warn().
				Str("backend", cb.name).
				Msg("circuit breaker reopened after half-open failure")
		}
		cb.mu.Unlock()

	case StateOpen:
		// Already open, just update timestamp
		failures := cb.failures.Add(1)
		log.Debug().
			Str("backend", cb.name).
			Int("failures", int(failures)).
			Msg("circuit breaker remains open")
	}
}

// transitionTo changes the circuit breaker state (caller must hold mu lock)
func (cb *CircuitBreaker) transitionTo(newState State) {
	oldState := State(cb.state.Load())
	cb.state.Store(int32(newState))
	cb.lastStateTime.Store(time.Now().UnixNano())

	// Reset counters on state change
	cb.requests.Store(0)

	// Update Prometheus metrics
	metrics.ProxyCircuitState.WithLabelValues(cb.name).Set(float64(newState))
	metrics.ProxyCircuitTransitions.WithLabelValues(cb.name, oldState.String(), newState.String()).Inc()

	log.Info().
		Str("backend", cb.name).
		Str("old_state", oldState.String()).
		Str("new_state", newState.String()).
		Msg("circuit breaker state transition")
}

// State returns the current circuit breaker state
func (cb *CircuitBreaker) State() State {
	return State(cb.state.Load())
}

// Stats returns current circuit breaker statistics
func (cb *CircuitBreaker) Stats() Stats {
	return Stats{
		Name:              cb.name,
		State:             State(cb.state.Load()),
		Failures:          int(cb.failures.Load()),
		Successes:         int(cb.successes.Load()),
		Requests:          int(cb.requests.Load()),
		LastFailTime:      time.Unix(0, cb.lastFailTime.Load()),
		LastStateTime:     time.Unix(0, cb.lastStateTime.Load()),
		FailureThreshold:  cb.config.FailureThreshold,
		SuccessThreshold:  cb.config.SuccessThreshold,
		Timeout:           cb.config.Timeout,
	}
}

// Stats holds circuit breaker statistics
type Stats struct {
	Name             string
	State            State
	Failures         int
	Successes        int
	Requests         int
	LastFailTime     time.Time
	LastStateTime    time.Time
	FailureThreshold int
	SuccessThreshold int
	Timeout          time.Duration
}

// Reset resets the circuit breaker to closed state (for testing/admin)
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state.Store(int32(StateClosed))
	cb.failures.Store(0)
	cb.successes.Store(0)
	cb.requests.Store(0)
	cb.lastStateTime.Store(time.Now().UnixNano())

	log.Info().
		Str("backend", cb.name).
		Msg("circuit breaker manually reset")
}

// Manager manages multiple circuit breakers (one per backend)
type Manager struct {
	config   Config
	breakers sync.Map // map[string]*CircuitBreaker
}

// NewManager creates a new circuit breaker manager
func NewManager(config Config) *Manager {
	return &Manager{
		config: config,
	}
}

// GetOrCreate returns the circuit breaker for a backend, creating if needed
func (m *Manager) GetOrCreate(backend string) *CircuitBreaker {
	// Fast path: breaker exists
	if val, ok := m.breakers.Load(backend); ok {
		return val.(*CircuitBreaker)
	}

	// Slow path: create new breaker
	cb := New(backend, m.config)
	actual, loaded := m.breakers.LoadOrStore(backend, cb)

	if !loaded {
		log.Info().
			Str("backend", backend).
			Int("failure_threshold", m.config.FailureThreshold).
			Int("success_threshold", m.config.SuccessThreshold).
			Dur("timeout", m.config.Timeout).
			Msg("created circuit breaker")
	}

	return actual.(*CircuitBreaker)
}

// GetAll returns all circuit breakers
func (m *Manager) GetAll() map[string]*CircuitBreaker {
	result := make(map[string]*CircuitBreaker)
	m.breakers.Range(func(key, value interface{}) bool {
		result[key.(string)] = value.(*CircuitBreaker)
		return true
	})
	return result
}

// Reset resets all circuit breakers
func (m *Manager) Reset() {
	m.breakers.Range(func(key, value interface{}) bool {
		value.(*CircuitBreaker).Reset()
		return true
	})
}
