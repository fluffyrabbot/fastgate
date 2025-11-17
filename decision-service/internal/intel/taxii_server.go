package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// TAXIIServer implements a TAXII 2.1 server for publishing indicators
type TAXIIServer struct {
	mu          sync.RWMutex
	bundles     []*bundleEntry
	collections map[string]*Collection
	maxBundles  int
}

type bundleEntry struct {
	bundle  *SimpleSTIXBundle
	created time.Time
}

// NewTAXIIServer creates a new TAXII server
func NewTAXIIServer() *TAXIIServer {
	return &TAXIIServer{
		bundles:     make([]*bundleEntry, 0, 1000),
		collections: make(map[string]*Collection),
		maxBundles:  1000,
	}
}

// RegisterCollection registers a new TAXII collection
func (s *TAXIIServer) RegisterCollection(id, title, description string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.collections[id] = &Collection{
		ID:          id,
		Title:       title,
		Description: description,
		CanRead:     true,
		CanWrite:    true,
	}
}

// PublishIndicator publishes an indicator to the TAXII server
func (s *TAXIIServer) PublishIndicator(ind *Indicator) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert to STIX indicator
	stixInd := toSimpleSTIXIndicator(ind)

	// Create bundle
	bundle := &SimpleSTIXBundle{
		Type: "bundle",
		ID:   fmt.Sprintf("bundle--%d", time.Now().UnixNano()),
		Objects: []SimpleSTIXIndicator{
			stixInd,
		},
	}

	entry := &bundleEntry{
		bundle:  bundle,
		created: time.Now(),
	}

	s.bundles = append(s.bundles, entry)

	// Limit bundle history (keep last maxBundles)
	if len(s.bundles) > s.maxBundles {
		s.bundles = s.bundles[len(s.bundles)-s.maxBundles:]
	}

	return nil
}

// HandleCollections handles GET /taxii2/collections/
func (s *TAXIIServer) HandleCollections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	collections := make([]Collection, 0, len(s.collections))
	for _, c := range s.collections {
		collections = append(collections, *c)
	}

	resp := struct {
		Collections []Collection `json:"collections"`
	}{
		Collections: collections,
	}

	w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
	json.NewEncoder(w).Encode(resp)
}

// HandleObjects handles GET /taxii2/collections/{id}/objects/
func (s *TAXIIServer) HandleObjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	addedAfterStr := r.URL.Query().Get("added_after")

	s.mu.RLock()
	defer s.mu.RUnlock()

	var filteredBundles []*bundleEntry

	if addedAfterStr != "" {
		t, err := time.Parse(time.RFC3339, addedAfterStr)
		if err == nil {
			for _, entry := range s.bundles {
				if entry.created.After(t) {
					filteredBundles = append(filteredBundles, entry)
				}
			}
		} else {
			filteredBundles = s.bundles
		}
	} else {
		filteredBundles = s.bundles
	}

	// Merge all bundles into one response
	mergedObjects := make([]SimpleSTIXIndicator, 0)
	for _, entry := range filteredBundles {
		mergedObjects = append(mergedObjects, entry.bundle.Objects...)
	}

	responseBundle := &SimpleSTIXBundle{
		Type:    "bundle",
		ID:      fmt.Sprintf("bundle--%d", time.Now().UnixNano()),
		Objects: mergedObjects,
	}

	w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
	json.NewEncoder(w).Encode(responseBundle)
}
