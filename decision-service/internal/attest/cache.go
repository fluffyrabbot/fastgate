package attest

import (
	"container/list"
	"sync"
	"time"
)

// tokenCache is a bounded LRU with TTL, keyed by opaque token strings.
type tokenCache struct {
	mu    sync.Mutex
	cap   int
	ttl   time.Duration
	items map[string]*list.Element
	lru   *list.List
}

type cacheVal struct {
	token  string
	ok     bool
	tier   string
	expiry time.Time
}

func newTokenCache(capacity int, ttl time.Duration) *tokenCache {
	if capacity <= 0 {
		capacity = 100_000
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &tokenCache{
		cap:   capacity,
		ttl:   ttl,
		items: make(map[string]*list.Element, capacity/2),
		lru:   list.New(),
	}
}

func (c *tokenCache) get(token string, now time.Time) (ok bool, tier string, hit bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, okm := c.items[token]; okm {
		val := el.Value.(*cacheVal)
		if now.Before(val.expiry) {
			c.lru.MoveToFront(el)
			return val.ok, val.tier, true
		}
		// expired
		delete(c.items, token)
		c.lru.Remove(el)
	}
	return false, "", false
}

func (c *tokenCache) put(token string, ok bool, tier string, ttl time.Duration) {
	if ttl <= 0 || ttl > c.ttl {
		ttl = c.ttl
	}
	now := time.Now()
	cv := &cacheVal{
		token:  token,
		ok:     ok,
		tier:   tier,
		expiry: now.Add(ttl),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, okm := c.items[token]; okm {
		el.Value = cv
		c.lru.MoveToFront(el)
		return
	}
	// Evict if needed
	if c.lru.Len() >= c.cap {
		if back := c.lru.Back(); back != nil {
			del := back.Value.(*cacheVal)
			delete(c.items, del.token)
			c.lru.Remove(back)
		}
	}
	el := c.lru.PushFront(cv)
	c.items[token] = el
}
