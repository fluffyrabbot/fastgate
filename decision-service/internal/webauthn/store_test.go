package webauthn

import (
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestStoreTakeConcurrentSingleWinner(t *testing.T) {
	s := NewStoreWithCapacity(time.Minute, 10)
	id := s.Put(&webauthn.SessionData{Challenge: "synthetic"}, []byte("user"), "/")
	const attempts = 16
	var ready, done sync.WaitGroup
	ready.Add(attempts)
	done.Add(attempts)
	results := make(chan bool, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			ready.Wait() // Release all contenders together.
			_, _, _, ok := s.Take(id)
			results <- ok
		}()
	}
	done.Wait()
	close(results)
	winners := 0
	for ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("single-use violation: got %d winners, want 1", winners)
	}
}

func TestStoreTakeExpiredAndMissing(t *testing.T) {
	s := NewStoreWithCapacity(-time.Second, 1)
	id := s.Put(&webauthn.SessionData{Challenge: "expired"}, []byte("user"), "/")
	for _, key := range []string{id, id, "missing"} {
		session, user, url, ok := s.Take(key)
		if ok || session != nil || user != nil || url != "" {
			t.Fatalf("Take(%q) returned unavailable session", key)
		}
	}
	if len(s.data) != 0 || s.lru.Len() != 0 {
		t.Fatal("expired entry still occupies storage")
	}
}
