package intel

import (
	"container/list"
	"sync"
	"time"
)

// Store is a thread-safe LRU cache for threat indicators with TTL-based expiration
type Store struct {
	mu       sync.RWMutex
	byType   map[IndicatorType]map[string]*list.Element // type -> value -> entry
	lru      *list.List
	cap      int
	gcTicker *time.Ticker
	stopCh   chan struct{}
}

type entry struct {
	indicator *Indicator
}

// NewStore creates a new indicator store with the given capacity
func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = 50000
	}

	s := &Store{
		byType:   make(map[IndicatorType]map[string]*list.Element),
		lru:      list.New(),
		cap:      capacity,
		gcTicker: time.NewTicker(5 * time.Minute),
		stopCh:   make(chan struct{}),
	}

	// Background GC for expired indicators
	go s.gcLoop()

	return s
}

// Add adds an indicator to the store
func (s *Store) Add(ind *Indicator) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Skip expired indicators
	if ind.IsExpired() {
		return
	}

	// Initialize type map if needed
	if s.byType[ind.Type] == nil {
		s.byType[ind.Type] = make(map[string]*list.Element)
	}

	// Check if already exists (update)
	if el, exists := s.byType[ind.Type][ind.Value]; exists {
		en := el.Value.(*entry)
		en.indicator = ind
		s.lru.MoveToFront(el)
		return
	}

	// Evict LRU if at capacity
	if s.lru.Len() >= s.cap {
		s.evictLRU()
	}

	// Add new
	en := &entry{indicator: ind}
	el := s.lru.PushFront(en)
	s.byType[ind.Type][ind.Value] = el
}

// Check checks if an indicator exists and is active
func (s *Store) Check(typ IndicatorType, value string) (*Indicator, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	typeMap, ok := s.byType[typ]
	if !ok {
		return nil, false
	}

	el, ok := typeMap[value]
	if !ok {
		return nil, false
	}

	en := el.Value.(*entry)
	if en.indicator.IsExpired() {
		return nil, false
	}

	return en.indicator, true
}

// Stats returns statistics about the store
// Close stops the background GC loop
func (s *Store) Close() {
	close(s.stopCh)
	s.gcTicker.Stop()
}

// evictLRU evicts the least recently used indicator (caller must hold lock)
func (s *Store) evictLRU() {
	back := s.lru.Back()
	if back == nil {
		return
	}

	en := back.Value.(*entry)
	ind := en.indicator

	delete(s.byType[ind.Type], ind.Value)
	s.lru.Remove(back)
}

// gcLoop runs periodic garbage collection
func (s *Store) gcLoop() {
	for {
		select {
		case <-s.gcTicker.C:
			s.gc()
		case <-s.stopCh:
			return
		}
	}
}

// gc removes expired indicators
func (s *Store) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for el := s.lru.Front(); el != nil; {
		next := el.Next()
		en := el.Value.(*entry)

		if now.After(en.indicator.ValidUntil) {
			delete(s.byType[en.indicator.Type], en.indicator.Value)
			s.lru.Remove(el)
		}

		el = next
	}
}
