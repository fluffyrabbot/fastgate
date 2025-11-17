package webauthn

import (
	"container/list"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Store manages WebAuthn challenge sessions with LRU eviction and TTL.
type Store struct {
	mu   sync.Mutex
	data map[string]*list.Element
	lru  *list.List
	ttl  time.Duration
	cap  int
}

type entry struct {
	id        string
	session   *webauthn.SessionData
	userID    []byte
	returnURL string
	expiresAt time.Time
}

// NewStore creates a new Store with the specified TTL and default capacity (10,000).
func NewStore(ttl time.Duration) *Store {
	return NewStoreWithCapacity(ttl, 10000)
}

// NewStoreWithCapacity creates a new Store with custom capacity.
func NewStoreWithCapacity(ttl time.Duration, capacity int) *Store {
	if capacity <= 0 {
		capacity = 10000
	}

	return &Store{
		data: make(map[string]*list.Element, capacity/2),
		lru:  list.New(),
		ttl:  ttl,
		cap:  capacity,
	}
}

// Put stores a WebAuthn session and returns a unique challenge ID.
func (s *Store) Put(session *webauthn.SessionData, userID []byte, returnURL string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate unique ID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	// Evict LRU if at capacity
	if s.lru.Len() >= s.cap {
		back := s.lru.Back()
		if back != nil {
			old := back.Value.(*entry)
			delete(s.data, old.id)
			s.lru.Remove(back)
		}
	}

	en := &entry{
		id:        id,
		session:   session,
		userID:    userID,
		returnURL: returnURL,
		expiresAt: time.Now().Add(s.ttl),
	}

	el := s.lru.PushFront(en)
	s.data[id] = el

	return id
}

// Get retrieves a WebAuthn session by challenge ID.
// Returns (session, userID, returnURL, found).
func (s *Store) Get(id string) (*webauthn.SessionData, []byte, string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	el, ok := s.data[id]
	if !ok {
		return nil, nil, "", false
	}

	en := el.Value.(*entry)

	// Check expiration
	if time.Now().After(en.expiresAt) {
		delete(s.data, id)
		s.lru.Remove(el)
		return nil, nil, "", false
	}

	// Touch LRU
	s.lru.MoveToFront(el)

	return en.session, en.userID, en.returnURL, true
}

// Consume removes a challenge from the store (idempotent).
func (s *Store) Consume(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if el, ok := s.data[id]; ok {
		delete(s.data, id)
		s.lru.Remove(el)
	}
}

// GC removes expired entries (best-effort cleanup).
func (s *Store) GC() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for el := s.lru.Back(); el != nil; {
		prev := el.Prev()
		en := el.Value.(*entry)

		if now.After(en.expiresAt) {
			delete(s.data, en.id)
			s.lru.Remove(el)
		}

		el = prev
	}
}
