package rate

import (
	"container/list"
	"log"
	"sync"
	"time"
)

/*
Package rate provides:
  1) SlidingRPS — bounded-memory, per-key sliding window RPS estimator
  2) Concurrency — bounded per-key concurrency gauge (for WS caps later)

Defaults are safe for MVP. You can tune capacities at construction time.
*/

// =========================
// Sliding RPS (bounded LRU)
// =========================

type SlidingRPS struct {
	mu      sync.Mutex
	window  int           // seconds
	cap     int           // max keys to retain
	items   map[string]*list.Element
	lru     *list.List    // front = most recently used
	nowFunc func() int64  // for tests; defaults to time.Now().Unix()
}

type rpsEntry struct {
	key      string
	startSec int64       // first second seen (for span calculation)
	lastSec  int64       // last updated second
	buckets  []uint16    // len == window; counts per second bucket
}

// NewSlidingRPS creates a 10k-capacity RPS estimator with a given window (seconds).
func NewSlidingRPS(window int) *SlidingRPS {
	return NewSlidingRPSWithCapacity(window, 10000)
}

// NewSlidingRPSWithCapacity creates a bounded RPS estimator.
func NewSlidingRPSWithCapacity(window, capacity int) *SlidingRPS {
	if window <= 0 {
		window = 10
	}
	if capacity <= 0 {
		capacity = 10000
	}
	return &SlidingRPS{
		window:  window,
		cap:     capacity,
		items:   make(map[string]*list.Element, capacity/2),
		lru:     list.New(),
		nowFunc: func() int64 { return time.Now().Unix() },
	}
}

// Add records an event for key and returns the estimated RPS across the recent window.
// It is O(window) per call (window is small, e.g., 10).
func (s *SlidingRPS) Add(key string) float64 {
	now := s.nowFunc()
	s.mu.Lock()
	defer s.mu.Unlock()

	// SECURITY: Monitor capacity to detect DoS attacks via key explosion
	currentSize := s.lru.Len()
	if currentSize > s.cap*90/100 {
		// Alert when approaching 90% capacity (only log occasionally to avoid spam)
		if currentSize%100 == 0 {
			log.Printf("SECURITY WARNING: rate limiter approaching capacity (%d/%d entries)", currentSize, s.cap)
		}
	}

	// Fast path: update existing entry
	if el, ok := s.items[key]; ok {
		en := el.Value.(*rpsEntry)
		s.advance(en, now)
		s.incrementTail(en)
		s.lru.MoveToFront(el)
		return s.estimate(en, now)
	}

	// New key
	if s.lru.Len() >= s.cap {
		// Evict LRU
		back := s.lru.Back()
		if back != nil {
			del := back.Value.(*rpsEntry)
			delete(s.items, del.key)
			s.lru.Remove(back)
		}
	}
	en := &rpsEntry{
		key:      key,
		startSec: now,
		lastSec:  now,
		buckets:  make([]uint16, s.window),
	}
	en.buckets[s.window-1] = 1
	el := s.lru.PushFront(en)
	s.items[key] = el
	return s.estimate(en, now)
}

// advance shifts the second-buckets forward to catch up with now.
func (s *SlidingRPS) advance(en *rpsEntry, now int64) {
	if now <= en.lastSec {
		return
	}
	diff := now - en.lastSec
	if diff >= int64(s.window) {
		// Too much time elapsed — zero everything
		for i := range en.buckets {
			en.buckets[i] = 0
		}
		en.startSec = now
		en.lastSec = now
		return
	}
	// Shift left by diff, zero-fill tail
	shift := int(diff)
	copy(en.buckets, en.buckets[shift:])
	for i := s.window - shift; i < s.window; i++ {
		en.buckets[i] = 0
	}
	en.lastSec = now
	// keep startSec as-is; span calc will clamp to window
}

func (s *SlidingRPS) incrementTail(en *rpsEntry) {
	// Saturate (uint16) to avoid overflow during extreme bursts
	if en.buckets[s.window-1] < 65535 {
		en.buckets[s.window-1]++
	}
}

func (s *SlidingRPS) estimate(en *rpsEntry, now int64) float64 {
	// Compute sum across window
	sum := 0
	for i := 0; i < s.window; i++ {
		sum += int(en.buckets[i])
	}
	// Compute effective span of seconds we actually covered:
	span := int(now - en.startSec + 1)
	if span < 1 {
		span = 1
	}
	if span > s.window {
		span = s.window
	}
	return float64(sum) / float64(span)
}

// ============================
// Concurrency gauge (bounded)
// ============================

type Concurrency struct {
	mu      sync.Mutex
	cap     int
	items   map[string]*list.Element
	lru     *list.List
	idleTTL time.Duration
	nowFunc func() time.Time
}

type concEntry struct {
	key      string
	count    int
	lastSeen time.Time
}

// NewConcurrency creates a bounded per-key concurrency gauge.
// Keys with zero count are eligible for LRU eviction; active keys are retained.
func NewConcurrency(capacity int) *Concurrency {
	if capacity <= 0 {
		capacity = 50000
	}
	return &Concurrency{
		cap:     capacity,
		items:   make(map[string]*list.Element, capacity/2),
		lru:     list.New(),
		idleTTL: 120 * time.Second,
		nowFunc: time.Now,
	}
}

// Acquire increments the counter for key if strictly below max.
// Returns (ok, current). If !ok, current is the existing count and caller should deny/queue.
func (c *Concurrency) Acquire(key string, max int) (bool, int) {
	if max <= 0 {
		return false, 0
	}
	now := c.nowFunc()
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		en := el.Value.(*concEntry)
		if en.count >= max {
			en.lastSeen = now
			c.lru.MoveToFront(el)
			return false, en.count
		}
		en.count++
		en.lastSeen = now
		c.lru.MoveToFront(el)
		return true, en.count
	}

	// New key: ensure capacity, evict idle zeros if needed
	c.evictIdleZeros(now)
	if c.lru.Len() >= c.cap {
		// If still full, refuse to track new key to remain bounded
		return false, 0
	}
	en := &concEntry{key: key, count: 1, lastSeen: now}
	el := c.lru.PushFront(en)
	c.items[key] = el
	return true, 1
}

// Release decrements the counter for key; no-op if missing.
func (c *Concurrency) Release(key string) {
	now := c.nowFunc()
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		en := el.Value.(*concEntry)
		if en.count > 0 {
			en.count--
		}
		en.lastSeen = now
		if en.count == 0 {
			// Move to back so it's the first to be evicted later
			c.lru.MoveToBack(el)
		} else {
			c.lru.MoveToFront(el)
		}
	}
}

// evictIdleZeros drops zero-count keys that haven't been seen recently.
func (c *Concurrency) evictIdleZeros(now time.Time) {
	if c.lru.Len() == 0 {
		return
	}
	for c.lru.Len() > 0 {
		back := c.lru.Back()
		en := back.Value.(*concEntry)
		if en.count == 0 && now.Sub(en.lastSeen) >= c.idleTTL {
			delete(c.items, en.key)
			c.lru.Remove(back)
			continue
		}
		// Stop once we reach an entry that is either active or not idle
		break
	}
}
