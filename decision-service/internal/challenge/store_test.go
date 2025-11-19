package challenge

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestStore_New(t *testing.T) {
	s := NewStore(time.Minute)
	id, nonce, err := s.New(12)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if id == "" || nonce == "" {
		t.Error("New returned empty id or nonce")
	}
	
	item, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if item.Bits != 12 {
		t.Errorf("expected 12 bits, got %d", item.Bits)
	}
}

func TestStore_TrySolve_Valid(t *testing.T) {
	s := NewStore(time.Minute)
	id, nonceB64, _ := s.New(12) // Min difficulty is 12

	nonce, _ := base64.RawURLEncoding.DecodeString(nonceB64)
	
	// Find a solution (brute force for 12 bits is fast enough)
	var solution uint32
	found := false
	for i := uint32(0); i < 1000000; i++ {
		if validateSolution(nonce, 12, i) {
			solution = i
			found = true
			break
		}
	}
	if !found {
		t.Fatal("could not find solution for 12 bits")
	}

	ok, reason, err := s.TrySolve(id, nonceB64, solution)
	if err != nil {
		t.Fatalf("TrySolve error: %v", err)
	}
	if !ok {
		t.Errorf("TrySolve failed: reason=%s", reason)
	}

	// Should be consumed
	_, err = s.Get(id)
	if err == nil {
		t.Error("Challenge should be consumed (deleted) after success")
	}
}

func TestStore_TrySolve_Invalid(t *testing.T) {
	s := NewStore(time.Minute)
	id, nonce, _ := s.New(12)

	// Wrong solution
	ok, reason, err := s.TrySolve(id, nonce, 999999999)
	if err != nil {
		t.Fatalf("TrySolve error: %v", err)
	}
	if ok {
		t.Error("TrySolve succeeded with wrong solution")
	}
	if reason != "invalid_solution" {
		t.Errorf("expected reason 'invalid_solution', got %q", reason)
	}

	// Should still exist (retries++ but not max)
	item, err := s.Get(id)
	if err != nil {
		t.Fatal("Challenge should still exist")
	}
	if item.Retries != 1 {
		t.Errorf("expected 1 retry, got %d", item.Retries)
	}
}

func TestStore_TrySolve_MaxRetries(t *testing.T) {
	s := NewStore(time.Minute)
	// Create with 1 max retry
	id, nonce, _ := s.NewWithMaxRetries(12, 1)

	// Fail 1: Retries -> 1. Still alive.
	s.TrySolve(id, nonce, 0)
	if _, err := s.Get(id); err != nil {
		t.Fatal("Challenge should exist after 1st failure")
	}

	// Fail 2: Retries -> 2. > Max (1). Consumed.
	ok, reason, _ := s.TrySolve(id, nonce, 0)
	if ok {
		t.Error("Should fail")
	}
	if reason != "too_many_retries" {
		t.Errorf("expected reason 'too_many_retries', got %q", reason)
	}

	// Should be gone
	if _, err := s.Get(id); err == nil {
		t.Error("Challenge should be consumed after max retries")
	}
}

func TestStore_Expired(t *testing.T) {
	s := NewStore(1 * time.Millisecond) // Instantly expires
	id, _, _ := s.New(12)

	time.Sleep(2 * time.Millisecond)

	_, err := s.Get(id)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestStore_LRU(t *testing.T) {
	s := NewStoreWithCapacity(time.Minute, 2)

	id1, _, _ := s.New(12)
	id2, _, _ := s.New(12)

	// Both exist
	if _, err := s.Get(id1); err != nil { t.Error("id1 missing") }
	if _, err := s.Get(id2); err != nil { t.Error("id2 missing") }

	// Add 3rd -> evicts id1 (LRU)
	// Note: Get(id1) above made it MRU? No, Get updates LRU. 
	// So: 
	// New(1), New(2). List: 2, 1.
	// Get(1). List: 1, 2.
	// New(3). Evicts 2 (LRU). List: 3, 1.
	
	// Let's verify that behavior.
	// Reset state for clarity
	s = NewStoreWithCapacity(time.Minute, 2)
	idA, _, _ := s.New(12) // [A]
	idB, _, _ := s.New(12) // [B, A]
	
	s.Get(idA) // [A, B] (A is now MRU)

	idC, _, _ := s.New(12) // [C, A] (B evicted)

	if _, err := s.Get(idB); err == nil {
		t.Error("idB should have been evicted")
	}
	if _, err := s.Get(idA); err != nil {
		t.Error("idA should still exist")
	}
	if _, err := s.Get(idC); err != nil {
		t.Error("idC should exist")
	}
}
