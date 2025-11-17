package intel

import (
	"context"
	"log"
	"sync"
	"time"
)

// Poller polls a TAXII feed for indicators and adds them to the store
type Poller struct {
	Client       *TAXIIClient
	Store        *Store
	Parser       *STIXParser
	CollectionID string
	Interval     time.Duration
	stopCh       chan struct{}
	stopOnce     sync.Once
}

// NewPoller creates a new TAXII poller
func NewPoller(client *TAXIIClient, store *Store, collectionID string, interval time.Duration) *Poller {
	return &Poller{
		Client:       client,
		Store:        store,
		Parser:       NewSTIXParser(),
		CollectionID: collectionID,
		Interval:     interval,
		stopCh:       make(chan struct{}),
	}
}

// Start starts the polling loop
func (p *Poller) Start() {
	ticker := time.NewTicker(p.Interval)
	defer ticker.Stop()

	// Initial fetch
	p.poll()

	for {
		select {
		case <-ticker.C:
			p.poll()
		case <-p.stopCh:
			return
		}
	}
}

// Stop stops the polling loop (idempotent - safe to call multiple times)
func (p *Poller) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})
}

// poll fetches and processes indicators
func (p *Poller) poll() {
	// Fetch indicators added in last polling interval
	addedAfter := time.Now().Add(-p.Interval)

	// Create context with timeout to prevent hanging requests
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	data, err := p.Client.FetchIndicators(ctx, p.CollectionID, addedAfter)
	if err != nil {
		log.Printf("TAXII fetch error (%s): %v", p.Client.BaseURL, err)
		return
	}

	indicators, err := p.Parser.ParseBundle(data)
	if err != nil {
		log.Printf("STIX parse error: %v", err)
		return
	}

	// Add to store
	for _, ind := range indicators {
		p.Store.Add(ind)
	}

	if len(indicators) > 0 {
		log.Printf("Fetched %d indicators from TAXII feed (%s)", len(indicators), p.Client.BaseURL)
	}
}
