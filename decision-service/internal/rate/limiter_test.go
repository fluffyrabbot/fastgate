package rate

import (
	"testing"
	"time"
)

// ---- SlidingRPS Tests ----

func TestSlidingRPS_Basic(t *testing.T) {
	// 10 second window
	rps := NewSlidingRPS(10)
	
	// Mock time: Start at T=100
	now := int64(100)
	rps.nowFunc = func() int64 { return now }

	// Add 5 requests at T=100
	for i := 0; i < 5; i++ {
		val := rps.Add("ip1")
		// 1st req: 1 req / 1 sec = 1.0
		// 5th req: 5 req / 1 sec = 5.0
		if i == 4 && val != 5.0 {
			t.Errorf("expected 5.0, got %f", val)
		}
	}

	// Move to T=101 (1 second later)
	now = 101
	// Add 5 more
	for i := 0; i < 5; i++ {
		rps.Add("ip1")
	}
	
	// Total: 10 requests over 2 seconds (100, 101)
	// RPS = 10 / 2 = 5.0
	// Wait, let's check the math. 
	// Buckets: [5, 5, 0...]
	// Sum = 10. Span = 101 - 100 + 1 = 2.
	// 10/2 = 5.0. Correct.
	
	val := rps.Add("ip1") // 11th request at T=101
	// Total 11 / 2 = 5.5
	if val != 5.5 {
		t.Errorf("expected 5.5, got %f", val)
	}
}

func TestSlidingRPS_Window(t *testing.T) {
	rps := NewSlidingRPS(2) // 2 second window
	now := int64(100)
	rps.nowFunc = func() int64 { return now }

	rps.Add("key") // T=100: 1. RPS=1/1=1
	rps.Add("key") // T=100: 2. RPS=2/1=2

	// Move to T=102 (2 seconds later). Window is [101, 102].
	// T=100 is now OUT of window.
	now = 102
	
	val := rps.Add("key") 
	// T=102: 1 new req.
	// Bucket T=100 (2 reqs) is gone.
	// Bucket T=101 (0 reqs).
	// Bucket T=102 (1 req).
	// Sum = 1. Span = 2 (101, 102).
	// RPS = 1 / 2 = 0.5?
	// Let's check logic: `span := int(now - en.startSec + 1)`. 
	// If advanced > window, startSec moves.
	// advance(102): diff=2. >= window(2). 
	// Reset buckets. startSec=102.
	// Add(102) -> bucket[0]=1.
	// Estimate: Sum=1. Span=102-102+1 = 1.
	// RPS = 1/1 = 1.0.
	
	if val != 1.0 {
		t.Errorf("expected 1.0 after window reset, got %f", val)
	}
}

// ---- Concurrency Tests ----

func TestConcurrency_Acquire(t *testing.T) {
	c := NewConcurrency(10)
	key := "user1"
	limit := 2

	// 1. Acquire 1 (OK)
	ok, cur := c.Acquire(key, limit)
	if !ok || cur != 1 {
		t.Errorf("1st acquire failed: ok=%v, cur=%d", ok, cur)
	}

	// 2. Acquire 2 (OK)
	ok, cur = c.Acquire(key, limit)
	if !ok || cur != 2 {
		t.Errorf("2nd acquire failed: ok=%v, cur=%d", ok, cur)
	}

	// 3. Acquire 3 (Fail - Max 2)
	ok, cur = c.Acquire(key, limit)
	if ok {
		t.Error("3rd acquire should fail")
	}
	if cur != 2 {
		t.Errorf("expected cur=2, got %d", cur)
	}
}

func TestConcurrency_Release(t *testing.T) {
	c := NewConcurrency(10)
	key := "user1"
	
	c.Acquire(key, 10) // 1
	c.Acquire(key, 10) // 2

	c.Release(key) // -> 1
	
	ok, cur := c.Acquire(key, 2) // -> 2 (OK)
	if !ok || cur != 2 {
		t.Errorf("re-acquire failed: ok=%v, cur=%d", ok, cur)
	}
}

func TestConcurrency_LRU(t *testing.T) {
	c := NewConcurrency(2) // Capacity 2
	
	c.Acquire("k1", 10)
	c.Acquire("k2", 10)
	
	// Both exist
	// Add k3 -> Should evict k1?
	// But k1 has count > 0. Concurrency limiters usually shouldn't evict ACTIVE keys?
	// The code says: `evictIdleZeros`. 
	// If no idle zeros, and capacity full: `return false, 0`.
	// So active keys prevent new keys if capacity is full.
	
	ok, _ := c.Acquire("k3", 10)
	if ok {
		t.Error("should fail to acquire new key when capacity full of active keys")
	}
	
	// Release k1 to 0
	c.Release("k1") 
	
	// Now k1 is idle zero. k3 should be able to evict it.
	// Wait, Release sets count=0. evictIdleZeros checks `now.Sub(lastSeen) >= idleTTL`.
	// So it won't evict immediately unless we mock time or wait.
	
	// Mock time
	mockTime := time.Now()
	c.nowFunc = func() time.Time { return mockTime }
	
	// Release k1 again to set lastSeen to mockTime
	c.Release("k1") // count is 0. lastSeen = mockTime.
	
	// Move time forward > idleTTL (120s)
	mockTime = mockTime.Add(130 * time.Second)
	c.nowFunc = func() time.Time { return mockTime }
	
	// Now acquire k3. It should trigger evictIdleZeros -> remove k1 -> success.
	ok, _ = c.Acquire("k3", 10)
	if !ok {
		t.Error("should acquire k3 after k1 expired")
	}
}
