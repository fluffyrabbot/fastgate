package intel

import (
	"testing"
	"time"
)

func TestStore_AddAndCheck(t *testing.T) {
	store := NewStore(10)
	defer store.Close()

	ind := &Indicator{
		ID:         "test-1",
		Type:       IndicatorIPv4,
		Value:      "192.0.2.1",
		Confidence: 80,
		ValidUntil: time.Now().Add(1 * time.Hour),
	}

	store.Add(ind)

	// Check existence
	retrieved, found := store.Check(IndicatorIPv4, "192.0.2.1")
	if !found {
		t.Fatal("Expected to find indicator")
	}
	if retrieved.Value != ind.Value {
		t.Errorf("Expected value %s, got %s", ind.Value, retrieved.Value)
	}
	if retrieved.Confidence != ind.Confidence {
		t.Errorf("Expected confidence %d, got %d", ind.Confidence, retrieved.Confidence)
	}

	// Check non-existence
	_, found = store.Check(IndicatorIPv4, "10.0.0.1")
	if found {
		t.Error("Found non-existent indicator")
	}
}

func TestStore_Expiration(t *testing.T) {
	store := NewStore(10)
	defer store.Close()

	ind := &Indicator{
		ID:         "expired-1",
		Type:       IndicatorIPv4,
		Value:      "192.0.2.2",
		ValidUntil: time.Now().Add(-1 * time.Minute), // Already expired
	}

	store.Add(ind)

	// Should not be found because Add skips expired items or Check validates expiry
	// The Add method has a check: if ind.IsExpired() { return }
	_, found := store.Check(IndicatorIPv4, "192.0.2.2")
	if found {
		t.Error("Found expired indicator")
	}
}

func TestStore_LRU_Eviction(t *testing.T) {
	capacity := 2
	store := NewStore(capacity)
	defer store.Close()

	// Add 1
	store.Add(&Indicator{Type: IndicatorIPv4, Value: "1.1.1.1", ValidUntil: time.Now().Add(time.Hour)})
	// Add 2
	store.Add(&Indicator{Type: IndicatorIPv4, Value: "2.2.2.2", ValidUntil: time.Now().Add(time.Hour)})

	// Both should exist
	if _, found := store.Check(IndicatorIPv4, "1.1.1.1"); !found {
		t.Error("1.1.1.1 should exist")
	}

	// Add 3 (should evict 1 because it was added first and not accessed? 
	// Wait, LRU behavior: accessing moves to front. We haven't accessed via Check in a way that updates LRU? 
	// Let's check the code. `Check` does RLock, so it DOES NOT update LRU order. 
	// Only `Add` (update) moves to front. 
	// So 1.1.1.1 is at the back.
	
	store.Add(&Indicator{Type: IndicatorIPv4, Value: "3.3.3.3", ValidUntil: time.Now().Add(time.Hour)})

	// 1 should be gone
	if _, found := store.Check(IndicatorIPv4, "1.1.1.1"); found {
		t.Error("1.1.1.1 should have been evicted")
	}
	// 2 and 3 should exist
	if _, found := store.Check(IndicatorIPv4, "2.2.2.2"); !found {
		t.Error("2.2.2.2 should exist")
	}
	if _, found := store.Check(IndicatorIPv4, "3.3.3.3"); !found {
		t.Error("3.3.3.3 should exist")
	}
}
