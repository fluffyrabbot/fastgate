package challenge

import (
	"container/list"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Item is an in-memory record for an issued challenge.
type Item struct {
	Nonce      []byte
	Bits       int
	ExpiresAt  time.Time
	Retries    int
	MaxRetries int
}

// Store keeps short-lived challenges with TTL and bounded cardinality via LRU.
type Store struct {
	mu   sync.Mutex
	data map[string]*list.Element
	lru  *list.List
	ttl  time.Duration
	cap  int
}

// NewStore creates a Store with default capacity (100k).
func NewStore(ttl time.Duration) *Store {
	return NewStoreWithCapacity(ttl, 100_000)
}

// NewStoreWithCapacity allows setting a custom capacity for outstanding challenges.
func NewStoreWithCapacity(ttl time.Duration, capacity int) *Store {
	if capacity <= 0 {
		capacity = 100_000
	}
	return &Store{
		data: make(map[string]*list.Element, capacity/2),
		lru:  list.New(),
		ttl:  ttl,
		cap:  capacity,
	}
}

// New mints a challenge with default maxRetries=2 (sane MVP default).
// Returns (challenge_id, nonce_b64url).
func (s *Store) New(bits int) (string, string, error) {
	return s.NewWithMaxRetries(bits, 2)
}

// NewWithMaxRetries mints a challenge with an explicit retry quota.
// Returns (challenge_id, nonce_b64url).
func (s *Store) NewWithMaxRetries(bits, maxRetries int) (string, string, error) {
	if bits < 12 || bits > 26 {
		bits = 16
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Capacity guard: evict LRU tail if full.
	if s.lru.Len() >= s.cap {
		back := s.lru.Back()
		if back != nil {
			old := back.Value.(*entry)
			delete(s.data, old.id)
			s.lru.Remove(back)
		}
	}

	en := &entry{
		id: id,
		it: Item{
			Nonce:      nonce,
			Bits:       bits,
			ExpiresAt:  now.Add(s.ttl),
			Retries:    0,
			MaxRetries: maxRetries,
		},
	}
	el := s.lru.PushFront(en)
	s.data[id] = el

	return id, base64.RawURLEncoding.EncodeToString(nonce), nil
}

// Get returns a snapshot copy of the item for id (or error).
// Note: returned Item is a copy to avoid external mutation races.
func (s *Store) Get(id string) (*Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.data[id]
	if !ok {
		return nil, errors.New("not found")
	}
	en := el.Value.(*entry)

	// Expired? purge and report.
	if time.Now().After(en.it.ExpiresAt) {
		delete(s.data, id)
		s.lru.Remove(el)
		return nil, errors.New("expired")
	}
	// Touch LRU.
	s.lru.MoveToFront(el)

	cp := en.it // copy
	return &cp, nil
}

// Consume removes the id if present (idempotent).
func (s *Store) Consume(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.data[id]; ok {
		delete(s.data, id)
		s.lru.Remove(el)
	}
}

// TrySolve validates the provided (nonce, solution) for the given id.
// It atomically updates retries, enforces MaxRetries & TTL, and consumes on:
//   - success (ok=true), or
//   - too many retries, or expiry.
//
// Returns (ok, reason, err):
//   ok=true,  reason="ok",                err=nil     -> valid solution, consumed
//   ok=false, reason="invalid_solution",  err=nil     -> still pending (retries++)
//   ok=false, reason="too_many_retries",  err=nil     -> consumed (retry cap)
//   ok=false, reason="expired",           err=nil     -> consumed (expired)
//   ok=false, reason="",                  err!=nil    -> unexpected/internal error
func (s *Store) TrySolve(id, nonceB64 string, solution uint32) (bool, string, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return false, "bad_nonce", nil
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.data[id]
	if !ok {
		return false, "not_found", nil
	}
	en := el.Value.(*entry)

	// Expired?
	if now.After(en.it.ExpiresAt) {
		delete(s.data, id)
		s.lru.Remove(el)
		return false, "expired", nil
	}

	// Nonce must match exactly (defense against replay/cross-mix).
	if !bytesEq(nb, en.it.Nonce) {
		// Do not consume; it's likely a confused client or replay.
		return false, "invalid_nonce", nil
	}

	// Validate PoW.
	if validateSolution(en.it.Nonce, en.it.Bits, solution) {
		// Success: consume.
		delete(s.data, id)
		s.lru.Remove(el)
		return true, "ok", nil
	}

	// Failed solution: increment retries and enforce cap.
	en.it.Retries++
	if en.it.Retries > en.it.MaxRetries {
		delete(s.data, id)
		s.lru.Remove(el)
		return false, "too_many_retries", nil
	}

	// Keep it, move to front; caller may try again.
	s.lru.MoveToFront(el)
	return false, "invalid_solution", nil
}

// ----- internals -----

type entry struct {
	id string
	it Item
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	// constant-time-ish compare (byte loop); good enough for nonce equivalence
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// validateSolution: SHA256(nonce || uint32_be(solution)) has >= bits leading zero bits.
func validateSolution(nonce []byte, bits int, solution uint32) bool {
	data := make([]byte, len(nonce)+4)
	copy(data, nonce)
	data[len(nonce)] = byte(solution >> 24)
	data[len(nonce)+1] = byte(solution >> 16)
	data[len(nonce)+2] = byte(solution >> 8)
	data[len(nonce)+3] = byte(solution)
	h := sha256.Sum256(data)
	return LeadingZeroBits(h[:]) >= bits
}

// LeadingZeroBits returns the count of leading zero bits in b.
func LeadingZeroBits(b []byte) int {
	n := 0
	for _, by := range b {
		for i := 7; i >= 0; i-- {
			if (by>>uint(i))&1 == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}

// ValidateSolution (exported) remains for backward compatibility.
func ValidateSolution(nonce []byte, bits int, solution uint32) bool {
	return validateSolution(nonce, bits, solution)
}
