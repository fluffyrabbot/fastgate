package intel

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// TAXIIClient is a client for fetching indicators from TAXII servers
type TAXIIClient struct {
	BaseURL    string
	Username   string
	Password   string
	HTTPClient *http.Client
}

// NewTAXIIClient creates a new TAXII client
func NewTAXIIClient(baseURL, username, password string) *TAXIIClient {
	return &TAXIIClient{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// FetchIndicators fetches indicators from a TAXII collection
func (c *TAXIIClient) FetchIndicators(collectionID string, addedAfter time.Time) ([]byte, error) {
	url := fmt.Sprintf("%s/taxii2/collections/%s/objects/", c.BaseURL, collectionID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}

	// Add filters
	q := req.URL.Query()
	if !addedAfter.IsZero() {
		q.Set("added_after", addedAfter.Format(time.RFC3339))
	}
	req.URL.RawQuery = q.Encode()

	// Set headers
	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TAXII server returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// ListCollections lists available TAXII collections
func (c *TAXIIClient) ListCollections() ([]Collection, error) {
	url := fmt.Sprintf("%s/taxii2/collections/", c.BaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}

	req.Header.Set("Accept", "application/taxii+json;version=2.1")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Collections []Collection `json:"collections"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Collections, nil
}

// Collection represents a TAXII collection
type Collection struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CanRead     bool   `json:"can_read"`
	CanWrite    bool   `json:"can_write"`
}
