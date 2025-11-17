package intel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// STIXParser parses STIX bundles into indicators
type STIXParser struct {
	ipv4Pattern *regexp.Regexp
	ipv6Pattern *regexp.Regexp
}

// NewSTIXParser creates a new STIX parser
func NewSTIXParser() *STIXParser {
	return &STIXParser{
		ipv4Pattern: regexp.MustCompile(`\[ipv4-addr:value\s*=\s*'([^']+)'\]`),
		ipv6Pattern: regexp.MustCompile(`\[ipv6-addr:value\s*=\s*'([^']+)'\]`),
	}
}

// SimpleSTIXIndicator represents a simplified STIX indicator for parsing
type SimpleSTIXIndicator struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	Pattern     string    `json:"pattern"`
	ValidFrom   time.Time `json:"valid_from"`
	ValidUntil  time.Time `json:"valid_until,omitempty"`
	Confidence  int       `json:"confidence,omitempty"`
	Labels      []string  `json:"labels,omitempty"`
	Description string    `json:"description,omitempty"`
}

// SimpleSTIXBundle represents a simplified STIX bundle
type SimpleSTIXBundle struct {
	Type    string                  `json:"type"`
	ID      string                  `json:"id"`
	Objects []SimpleSTIXIndicator   `json:"objects"`
}

// ParseBundle parses a STIX bundle and returns indicators
func (p *STIXParser) ParseBundle(data []byte) ([]*Indicator, error) {
	var bundle SimpleSTIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshal bundle: %w", err)
	}

	indicators := make([]*Indicator, 0, len(bundle.Objects))

	for _, obj := range bundle.Objects {
		if obj.Type != "indicator" {
			continue
		}

		ind := p.convertIndicator(&obj)
		if ind != nil {
			indicators = append(indicators, ind)
		}
	}

	return indicators, nil
}

// convertIndicator converts a STIX indicator to our internal format
func (p *STIXParser) convertIndicator(stixInd *SimpleSTIXIndicator) *Indicator {
	// Parse pattern: "[ipv4-addr:value = '192.0.2.1']"
	typ, value, err := p.parseSTIXPattern(stixInd.Pattern)
	if err != nil {
		return nil
	}

	validFrom := stixInd.ValidFrom
	validUntil := stixInd.ValidUntil
	if validUntil.IsZero() {
		validUntil = validFrom.Add(24 * time.Hour) // Default 24h TTL
	}

	confidence := stixInd.Confidence
	if confidence == 0 {
		confidence = 50 // Default medium confidence
	}

	// Extract description
	description := stixInd.Description
	if description == "" {
		description = "Threat indicator"
	}

	return &Indicator{
		ID:          stixInd.ID,
		Type:        typ,
		Value:       value,
		Confidence:  confidence,
		ValidFrom:   validFrom,
		ValidUntil:  validUntil,
		Labels:      stixInd.Labels,
		Description: description,
		Source:      "external",
	}
}

// parseSTIXPattern parses a STIX pattern and extracts the indicator type and value
func (p *STIXParser) parseSTIXPattern(pattern string) (IndicatorType, string, error) {
	// Try IPv4 pattern
	if matches := p.ipv4Pattern.FindStringSubmatch(pattern); len(matches) > 1 {
		return IndicatorIPv4, matches[1], nil
	}

	// Try IPv6 pattern
	if matches := p.ipv6Pattern.FindStringSubmatch(pattern); len(matches) > 1 {
		return IndicatorIPv6, matches[1], nil
	}

	return "", "", fmt.Errorf("unsupported pattern: %s", pattern)
}

// CreateBundle creates a STIX bundle from indicators
func CreateBundle(indicators []*Indicator) ([]byte, error) {
	objects := make([]SimpleSTIXIndicator, 0, len(indicators))

	for _, ind := range indicators {
		stixInd := toSimpleSTIXIndicator(ind)
		objects = append(objects, stixInd)
	}

	bundle := SimpleSTIXBundle{
		Type:    "bundle",
		ID:      fmt.Sprintf("bundle--%d", time.Now().UnixNano()),
		Objects: objects,
	}

	return json.Marshal(bundle)
}

// toSimpleSTIXIndicator converts our internal indicator to STIX format
func toSimpleSTIXIndicator(ind *Indicator) SimpleSTIXIndicator {
	pattern := fmt.Sprintf("[%s:value = '%s']", ind.Type, ind.Value)

	return SimpleSTIXIndicator{
		Type:        "indicator",
		ID:          ind.ID,
		Pattern:     pattern,
		ValidFrom:   ind.ValidFrom,
		ValidUntil:  ind.ValidUntil,
		Labels:      ind.Labels,
		Confidence:  ind.Confidence,
		Description: ind.Description,
	}
}
