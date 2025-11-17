package intel

import "time"

// IndicatorType represents the type of threat indicator
type IndicatorType string

const (
	IndicatorIPv4      IndicatorType = "ipv4-addr"
	IndicatorIPv6      IndicatorType = "ipv6-addr"
	IndicatorUserAgent IndicatorType = "user-agent"
	IndicatorPattern   IndicatorType = "pattern"
)

// Indicator represents a threat intelligence indicator
type Indicator struct {
	ID          string        `json:"id"`
	Type        IndicatorType `json:"type"`
	Value       string        `json:"value"`
	Confidence  int           `json:"confidence"`  // 0-100
	ValidFrom   time.Time     `json:"valid_from"`
	ValidUntil  time.Time     `json:"valid_until"`
	Labels      []string      `json:"labels"`
	Source      string        `json:"source"`
	Description string        `json:"description"`
}

// IsExpired checks if the indicator has expired
func (i *Indicator) IsExpired() bool {
	return time.Now().After(i.ValidUntil)
}

// IsActive checks if the indicator is currently active
func (i *Indicator) IsActive() bool {
	now := time.Now()
	return now.After(i.ValidFrom) && now.Before(i.ValidUntil)
}
